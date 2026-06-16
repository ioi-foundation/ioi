# Hypervisor Kernel Substrate Unification Master Guide

Status: implementation master guide.
Canonical intent: resolve the current Hypervisor daemon and Rust/WASM kernel/workload split brain without introducing a new runtime beside the daemon.
Primary owner candidate: architecture meta until promoted into component canon.
Last alignment pass: 2026-06-15.
Last pruning alignment: 2026-06-12. The migration matrix is now a compact macro
ledger; future guide updates should steer macro authority cuts instead of
per-slice evidence accumulation.

## How To Use This Guide

This guide has three jobs:

1. Give architects the clean target shape for Hypervisor, the daemon, the
   Rust/WASM substrate, Agentgres, wallet.network, cTEE, and Hypervisor IDE.
2. Give implementers enough low-level structure to migrate the current repo
   without creating another split brain.
3. Define the completion contract for the implementation migration itself.

Read it by role:

| Reader | Start here | Then read |
| --- | --- | --- |
| System architect | One-Page Doctrine | Part I, Part II, Final Doctrine |
| Runtime implementer | One-Page Doctrine | Part III, Part IV, Part VII |
| Hypervisor IDE / workflow implementer | One-Page Doctrine | Part V, Part VI, Part VII |
| Agentgres / receipt implementer | One-Page Doctrine | Part III, Part IV |
| cTEE / private workspace implementer | One-Page Doctrine | Part II, Part III, Part VII |
| Migration lead | One-Page Doctrine | Part VII, Part VIII, Part IX |

The document is layered from high level to low level:

```text
One-Page Doctrine
  -> current split brain
  -> target ownership model
  -> Step/Module ABI
  -> truth, receipts, replay, and projections
  -> workflow compositor and governed self-improvement
  -> migration program and anti-patterns
```

Nothing here should be read as a request to create a second runtime beside the
daemon. The entire guide exists to converge the current product daemon and the
existing Rust/WASM kernel/workload substrate into one authoritative execution
architecture.

Completion of this guide means execution, not publication. The guide is
complete only when the migration program has been carried through terminal
conformance and the split brain no longer exists. There is no separate
"future migration" after the master guide is carried out; anything after that is
ordinary product/runtime evolution.

Historical slice notes below are retained only where they anchor existing
conformance evidence. They are not scheduling doctrine. New migration work
should update the compact matrix only when a macro authority boundary changes.

## One-Page Doctrine

The long-term shape is not:

```text
Rewrite Hypervisor from scratch in Rust.
```

It is:

```text
Keep the Hypervisor Daemon as the product/control authority boundary.
Route consequential daemon steps through the existing Rust/WASM
kernel/workload substrate as the authoritative step/module execution backend.
Record admitted truth in Agentgres.
Authorize through wallet.network.
Project the same graph into Hypervisor IDE.
Use cTEE Private Workspace profiles when untrusted compute must not receive
protected plaintext custody.
```

Short form:

```text
Hypervisor Daemon owns execution semantics.
Default Harness Profile configures loop-native orchestration.
Rust/WASM workload/kernel executes admitted step modules.
Agentgres admits and proves operational truth.
wallet.network authorizes.
Hypervisor IDE composes and inspects the same graph.
```

This guide is intentionally honest about what exists today versus what is the
target. It should prevent two common mistakes:

1. Treating the existing Rust/WASM substrate as irrelevant because the live
   product daemon is Node/JS.
2. Treating the Rust/WASM substrate as a peer runtime that replaces daemon
   authority instead of sitting underneath it.

### End state in one diagram

```text
Hypervisor IDE / CLI / SDK
  request, compose, inspect, approve, replay
        |
        v
Hypervisor Daemon
  execution owner, authority/effect boundary
        |
        v
Default Harness Profile
  daemon-executed loop-native orchestration profile
        |
        v
StepModuleRouter
  canonical bridge from daemon loop steps to execution backends
        |
        +-- daemon-native tool during migration
        +-- Rust/WASM service module
        +-- Rust workload container job
        +-- model/inference mount
        +-- cTEE Private Workspace action
        +-- verifier module
        +-- AIIP / capability exit
        |
        v
Agentgres + receipts + artifact refs + state roots
  admitted operational truth and replay/restore authority
```

### Five invariants

| Invariant | Meaning |
| --- | --- |
| One execution owner | Hypervisor Daemon owns execution semantics and effect boundaries. |
| One orchestration profile | Default Harness Profile configures daemon-executed loop-native work. |
| One step/module contract | Every serious step is represented as a `StepModuleInvocation` and result. |
| One admitted truth path | Agentgres admits meaningful operations, receipts, refs, heads, and state roots. |
| One migration direction | JS product paths converge into a Rust daemon core and Rust/WASM backend; obsolete shims are deleted after verification. |

### Concept ladder

| Layer | User sees | Implementer builds | Canon boundary |
| --- | --- | --- | --- |
| Product surface | Hypervisor IDE/CLI/SDK workflow | workflow graph, approvals, replay, package UX | product requests and inspection only |
| Daemon authority | a run that can act safely | gates, leases, StepModuleRouter, cTEE checks | execution semantics live here |
| Harness profile | loop-native autonomous work | ActionProposal -> GateResult -> module execution -> observation | Default Harness Profile configures, does not replace daemon |
| Execution backend | tool/model/worker/service progress | Rust/WASM service modules, workload jobs, model mounts, verifiers | backend executes admitted steps |
| Truth substrate | receipts, evidence, restore/replay | Agentgres operations, refs, heads, state roots | admitted operational truth |
| Settlement surface | marketplace/public/cross-domain proof when needed | L1/app-chain commitments by trigger | not default runtime settlement |

## Part I: Current Split Brain

This part establishes the present repo reality: what is live product runtime,
what is lower protocol/kernel substrate, what exists only as canon target, and
where the split brain actually lives.

### Current repo evidence

The repo already contains a serious Rust kernel/workload substrate:

| Area | Current evidence | Architectural meaning |
| --- | --- | --- |
| Rust workspace | `Cargo.toml` includes `crates/node`, `crates/validator`, `crates/ipc`, `crates/vm/wasm`, `crates/services`, `crates/client`, and related state/consensus crates. | IOI already has protocol/kernel code, not only product JS. |
| Wasmtime VM | `crates/vm/wasm/src/lib.rs` defines `WasmRuntime` with component-model support, fuel, state host calls, inference host calls, GUI/browser host calls, and `VirtualMachine::execute`. | The runtime kernel can execute WASM service components with bounded fuel and host capabilities. |
| WASM service wrapper | `crates/vm/wasm/src/wasm_service.rs` wraps a WASM module as an `UpgradableService` / `BlockchainService`. | Service modules can be execution units in a state-machine/domain-kernel setting. |
| Workload container | `crates/validator/src/standard/workload/README.md` describes the Workload container as the isolated execution plane. | The lower substrate already separates orchestrator, workload, and guardian roles. |
| Hybrid IPC | `crates/ipc/README.md` and `crates/ipc/src/lib.rs` define gRPC control plane plus shared-memory/rkyv data plane. | The substrate has a low-latency control plane and high-bandwidth payload path. |
| Shared-memory data plane | `crates/client/src/shmem.rs` manages memory-mapped data and `ShmemHandle` offsets/lengths. | Large blocks, contexts, tensors, and payloads can avoid repeated protobuf serialization and deserialization. |
| Blockchain control path | `crates/validator/src/standard/workload/ipc/grpc_blockchain.rs` accepts inline block bytes or shared-memory handles. | Domain-kernel state transitions can use the data plane. |
| Workload control path | `crates/validator/src/standard/workload/ipc/grpc_control.rs` exposes `LoadModel` and `ExecuteJob` and coordinates shared-memory input. | Inference/workload jobs already have a lower control-plane surface. |
| Agentic runtime kernel | `crates/services/src/agentic/runtime/kernel/*` defines shared bounded-runtime primitives, invocation envelopes, policy, capability, evidence, trace, settlement, and profile checks. | There is already Rust-side language for governed agent invocations. |
| Harness projection adapter | `crates/services/src/agentic/runtime/harness.rs` says it lifts runtime kernels into stable workflow-addressable component frames and does not replace the live runtime executor. | This is a direct bridge hint: projection exists before full live execution migration. |

The repo also contains extensive product-facing Hypervisor daemon infrastructure:

| Area | Current evidence | Architectural meaning |
| --- | --- | --- |
| Node daemon package | `packages/runtime-daemon/package.json` is `@ioi/runtime-daemon`, ESM, Node >= 18. | The live product daemon is still Node/JS. |
| HTTP daemon service | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs` creates an HTTP server and local state dir under `.ioi/agentgres`. | Product runtime control is currently HTTP/JS, not native workload IPC by default. |
| Tool dispatch | `packages/runtime-daemon/src/coding-tools.mjs` dispatches coding tools through JS functions such as `workspace.status`, `git.diff`, `file.apply_patch`, `test.run`, and `lsp.diagnostics`. | The live coding-agent step path is direct daemon-native JS tool execution. |
| Approval routes | `packages/runtime-daemon/src/runtime-route-handlers.mjs` exposes thread approvals, tool invocation, events, replay, trace, and inspect routes. | The daemon owns product UX/control surfaces. |
| Runtime event envelopes | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` maps runtime events into workflow-node, component-kind, receipt-ref, artifact-ref, policy-ref projections. | The daemon already has the projection vocabulary needed by the IDE. |
| Model mounting | `packages/runtime-daemon/src/model-mounting/*` stores model artifacts, routes, providers, instances, vault refs, receipts, and projections. | Model mounting is currently product-daemon state, with Agentgres-like receipt/operation hooks. |
| Retired runtime-service command bridge | The old JS RuntimeAgentService command adapter, `RuntimeApiBridge` adapter surface, `runtime-api-bridge.mjs` module, `ioi-runtime-bridge` binary, bridge env policy overrides, and deleted runtime-service helper are retired. The daemon rejects `runtimeBridge` options. | Runtime-service execution must return through stable Rust daemon-core protocol/API ownership, not a revived Node command/env or binary bridge. |

The architecture docs already name the intended boundaries:

| Canon doc | Current doctrine |
| --- | --- |
| `docs/architecture/components/daemon-runtime/default-harness-profile.md` | The Default Harness Profile is daemon-executed, not a separate runtime beside the daemon. |
| `docs/architecture/foundations/domain-kernels.md` | IOI kernel / L0 substrate creates and operates many domain kernels and governed chains. |
| `docs/architecture/foundations/governed-autonomous-systems.md` | Serious autonomous systems are governed execution objects whose service modules produce receipted transitions. |
| `docs/architecture/components/daemon-runtime/private-workspace-ctee.md` | Private Workspace backed by cTEE is the daemon profile for no-plaintext-custody work on rented GPU nodes. |
| `docs/architecture/components/wallet-network/doctrine.md` | wallet.network owns authority, secrets, approvals, decryption leases, cTEE authority view, and capability exit authorization. |

### Live product runtime

Live product runtime today is primarily:

```text
Hypervisor IDE / agent-ide surfaces
  -> @ioi/runtime-daemon HTTP routes
  -> JS state store / thread store / model-mounting store
  -> JS direct tool dispatch for local coding tools
  -> runtime event envelope projections
  -> approvals, receipts, replay, trace, model routes
```

This is good enough to ship product UX and prove user-facing workflows. It is
not yet the final substrate for all serious autonomous work.

### Protocol/kernel substrate

The Rust protocol/kernel substrate already includes:

```text
IOI kernel/domain state-machine machinery
Workload container
WASM VM/service modules
gRPC control plane
shared-memory/rkyv data plane
guardian/workload/orchestration split
inference runtime hooks
agentic runtime kernel envelopes
service module and module invocation concepts
state roots, workload receipts, block/transaction processing
```

This is lower than product UX. It should become the authoritative backend for
step/module execution, but it should not become a separate user-facing runtime
beside Hypervisor Daemon.

### Target pieces not fully wired

These pieces are conceptually aligned but not fully wired end to end:

| Target | Present state |
| --- | --- |
| One Step/Module ABI across daemon, workload, service modules, worker packages, service packages, verifiers, model mounts, and cTEE actions | In migration. Shared invocation/result envelopes exist, coding-tool and model-mount projections bind into the ABI, and worker/service, cTEE, settlement, and governed-improvement admission paths use stable StepModule-facing APIs; remaining work is terminal extraction of every hot route into one Rust daemon core. |
| Daemon tool step routed through workload client into Rust/WASM service module | Current conformance requires migrated coding-tool execution to call `daemonCoreWorkloadApi.runCodingToolStepModule` directly from the daemon invocation surface, keeps the temporary StepModule runner facade deleted, rejects command/backend/env fallback shapes, and removes the retired JS coding-tool dispatcher from live invocation. Remaining work is broader JS facade retirement around non-migrated route families. |
| Agentgres operation/state-root unification across daemon local state and domain-kernel state | In migration. Runtime run-state persistence now commits through Rust Agentgres admission with expected heads, state roots, materialized records, storage admissions, and projection watermarks; remaining JS receipt/cache persistence must continue demoting behind Rust binding/admission. |
| Workflow compositor as live graph controller over the same runtime substrate | In migration. Rust projection records and accepted-truth guards exist, and IDE/SDK/daemon projection aliases are being retired; deeper live package/review UI remains ordinary product work on top of admitted projection APIs. |
| cTEE Private Workspace as concrete workload/module path | Implemented at the admission path: Rust validation/execution/admission/projection bundle, daemon runner, product/API route, SDK/IDE/CLI clients, and plaintext negative conformance exist. Deeper private workspace UI/replay remains product work. |
| Meta self-improvement as proposal-mediated module/profile/schema changes | Implemented at the admission path: governed proposal admission requires eval/verifier receipts, approval, rollback, Agentgres binding, expected heads, and state roots; full IDE review UI and live mutation commit remain product/runtime evolution. |

### Where the split brain lives

The split brain is not conceptual anymore. The doctrine is mostly correct. The
split brain is implementation placement:

```text
Live product harness step:
  Node/JS daemon route -> JS tool function -> JS event/receipt/projection

Lower protocol step:
  Rust workload/control plane -> WASM service or workload job -> state root / receipt / block event
```

The long-term fix is a stable daemon-to-kernel protocol surface, not a
permanent bridge binary:

```text
Daemon ActionProposal
  -> wallet.network / daemon GateResult
  -> StepModuleRouter
  -> direct daemon-native tool OR Rust/WASM module OR workload job OR model mount
  -> ExecutionResult
  -> NormalizedObservation
  -> Receipt + ArtifactRef + Agentgres operation
  -> workflow compositor projection
```

The former `ioi-step-module-bridge` command path was migration scaffolding for
the Node/JS facade while Rust ownership was being proven route by route. It is
now retired for daemon hot paths: the bridge binary and empty root tombstone are
deleted, conformance guards their absence, and any future daemon/kernel protocol
transport must be a stable Rust daemon-core API surface with no independent
execution authority, no compatibility-shim semantics, and no duplicate truth
path.

Current sprint note: Slices 924, 1232, and 1262 retired the
`IOI_STEP_MODULE_COMMAND_ARGS`/constructor-`args` selectors and then deleted the
temporary runtime-daemon StepModule runner facade. The JS edge may no longer
shape argv, select command/backend/env compatibility, or preserve runner
fallback semantics; migrated coding-tool execution now reaches Rust through the
typed `daemonCoreWorkloadApi.runCodingToolStepModule` API from the invocation
surface itself.
Slice 925 applies the same fixed-argv rule to the worker/service package, L1
settlement, cTEE private workspace, external capability authority, and governed
meta-improvement daemon-core runners by retiring `IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`
and constructor-`args` for those surfaces. Later authority cuts replace those
families with typed Rust daemon-core APIs and retire their generic command
operation entries, while other route families still need the same transport
retirement.
Slice 926 extends the fixed-argv rule to coding-tool approval, approval-state,
context-policy/state-update, runtime Agentgres admission, and workspace-restore
daemon-core runners. The remaining command-transport shape is still migration
scaffolding, not the target Rust daemon-core API.
Slice 927 extends the fixed-argv rule to the model_mount core. The
JS edge can no longer use `IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS` or constructor
`args` to shape daemon-core argv for model_mount core, provider execution,
receipt binding, or projection planning. This still leaves command transport as
temporary migration scaffolding; the terminal target remains direct Rust
daemon-core protocol/API ownership with no JS-authoritative model_mount hot path.
Slice 928 extends the same fixed-argv retirement to the RuntimeAgentService
command adapter. `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS`,
`IOI_RUNTIME_BRIDGE_ARGS`, and constructor `args` can no longer shape the
runtime-agent service bridge command. The configured command must be executable
as the transport endpoint itself until the temporary bridge collapses into the
stable daemon protocol/API and Rust daemon-core ownership.

Slice 1034 completed the scheduled post-Slice-1033 matrix-compaction pass. The
migration matrix now preserves expanded implementation evidence through Slices
941-1033 in compacted summaries, including the model-mount required-record
child owner split, while keeping the same terminal target: direct Rust
daemon-core APIs over Agentgres-backed truth, receipt/state-root binding,
wallet.network authority where applicable, cTEE custody, replay, projection,
and stable protocol APIs must still replace command transport and JS edge
translation before completion can be claimed. No matrix-compaction pass is
pending until the next larger Rust-core extraction or facade-retirement seam
lands.

Resume-goal scheduling marker: the Slice 733-740 matrix-compaction pass is
complete, and the Slice 741 thread-memory control facade-retirement
matrix-compaction pass is complete. The Slice 742 thread runtime-control
facade-retirement matrix-compaction pass is complete. The Slice 743
workspace-trust control facade-retirement matrix-compaction pass is complete.
The Slice 744 workspace-change and managed-session control facade-retirement
matrix-compaction pass is complete. Slice 745 retired the MCP workflow
import/ephemeral-registration/tool-invocation/workflow-node execution JS
facades before JS receipt synthesis, record-state commits, authorization,
fixture tool execution, route tests, receipt-gate dispatch, or model invocation,
and the Slice 745 MCP workflow facade-retirement matrix-compaction pass is
complete. Slice 746 retired the model-mount conversation-state write and
stream-completion finalization JS facades before JS `model-conversations`
record-state commits, conversation map mutation, JS
`model_invocation_stream_completed` receipt synthesis, receipt-binding request
construction, Agentgres transition planning, or projection writes.
The Slice 746 model conversation/stream completion facade-retirement
matrix-compaction pass is complete.
Slice 747 retired model-mount tokenizer/count/context-fit JS utility facades
before JS authorization, route selection, route receipt creation,
`model_tokenization`/`model_context_fit` receipt synthesis, route mutation,
truncation, or response-envelope shaping.
The Slice 747 model tokenizer/context-fit facade-retirement matrix-compaction
pass is complete.
Slice 748 retired the direct model lifecycle receipt helper before JS
`model_lifecycle` receipt construction, state receipt delegation, store writes,
or projection refresh.
The Slice 748 direct model lifecycle receipt helper facade-retirement
matrix-compaction pass is complete.
Slice 749 retired the public model invocation and stream invocation JS facades
before JS authorization, route selection, route-selection receipt creation,
provider execution, MCP integration compilation, JS invocation receipt creation,
receipt binding, Agentgres transition planning, conversation projection,
route-state persistence, or stream fallback.
The Slice 749 public model invocation facade-retirement matrix-compaction pass
is complete.
Slice 750 retired the explicit runtime model-route selection JS facade before
`modelMounting.selectRoute`, JS route-selection receipt construction,
model-route binding from a JS receipt, or fallback receipt minting. Persisted
agent route readback without a model override remains projection-only until
direct Rust projection APIs replace it.
Slice 751 first routed OpenAI-compatible stream cancellation through Rust
`plan_model_mount_stream_cancel`; Slice 1221 later moved stream cancellation to
typed `daemonCoreModelMountApi.planModelMountStreamCancel`, backed by
`RuntimeKernelService::plan_model_mount_stream_cancel`, and retired the old
command operation/dispatch/wrapper/backend path. Rust still authors the
`model_invocation_stream_canceled` receipt, accepted-receipt transition,
StepModule binding, Agentgres admission, and canceled conversation projection
before the JS protocol adapter can return or persist stream-cancel truth.
The receipt-gate boundary now has a positive Rust daemon-core planner.
Receipt-gate validation calls `plan_model_mount_receipt_gate`, passes canonical
receipt facts and required tool receipt ids to Rust, receives a Rust-authored
`workflow_receipt_gate` or `workflow_receipt_gate_blocked` receipt with
receipt-binder and Agentgres gate evidence, and persists only that receipt
through Rust Agentgres model_mount receipt-state admission. JS no longer
computes gate failures or authors gate receipts.
The Slice 731 coding-tool artifact mutation compaction is complete, and the
Slice 732 workspace snapshot/restore mutation compaction is complete. The Slice
733-740 runtime bridge thread/turn, runtime subagent, runtime task/job,
thread-fork, conversation-artifact, permanent agent-delete, and agent
lifecycle/status-control facade-retirement compaction is complete. The Slice 741
thread-memory control facade-retirement compaction is complete. The Slice 742
thread runtime-control facade-retirement compaction is complete. The Slice 743
workspace-trust control facade-retirement compaction is complete. The Slice 744
workspace-change and managed-session control facade-retirement compaction is
complete. Slice 745 MCP workflow facade-retirement compaction is complete. The
Slice 746 model conversation/stream completion facade-retirement compaction is
complete. Slice 747 model tokenizer/context-fit facade-retirement compaction is
complete. Slice 748 direct model lifecycle receipt helper facade-retirement
compaction is complete. Slice 749 public model invocation facade-retirement
compaction is complete. Slice 750 runtime model-route selection facade
retirement compaction is complete. Slice 751 stream-cancel positive Rust API
compaction is complete. Slice 752 receipt-gate receipt facade
retirement is superseded by the Rust receipt-gate planner. Slice 753 public model invocation dead JS
body-retirement compaction is complete. Slice 754 retired model invocation
migration-helper compatibility aliases and its compaction is complete. Slice
755 retired the daemon workflow-edit proposal/approval read-helper facades that
remained after workflow-edit apply authority was first moved behind fail-closed
admission. Workflow-edit execution is still not terminal: proposal/apply control
events now require Rust workflow-edit control planning and runtime-event
admission, but approved apply still requires Rust daemon-core mutation admission,
Agentgres expected-head/state-root binding, receipt/event materialization,
projection, and replay before it can execute again. The Slice
755 workflow-edit read-helper facade-retirement compaction is complete. The
Slice 755 workflow-edit read-helper facade-retirement matrix-compaction is
complete.
Slice 756 retired backend-process plan/load-option compatibility aliases from
the Rust model_mount process-plan boundary and local provider load paths:
`contextLength`, `maxModelLen`, `tensorParallelSize`,
`gpuMemoryUtilization`, `modelPath`, `embedding`, `defaults.contextLength`, and
`body.loadOptions` can no longer steer Rust-facing backend process planning.
This does not claim terminal model_mount lifecycle migration: direct Rust
daemon-core model_mount lifecycle/planning APIs still need to own backend
process planning, provider lifecycle admission, receipt/state-root binding,
Agentgres admission, projection, and replay. The Slice 756 backend-process
plan/load-option alias-retirement matrix-compaction pass is complete.
Slice 757 retired local `server-state.json` readback from public model server
status projection, so stale local cache files can no longer supply
server-control status, operation, timestamp, or receipt truth. This does not
claim terminal model_mount server-control migration: direct Rust daemon-core
server-control/state/log/event/projection APIs still need to own server status,
control state, log/event projection, receipt binding, Agentgres admission, and
replay. The Slice 757 server-control local cache read-retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands. Future
compactions must preserve evidence, distinguish interim bridge scaffolding,
canonical JS input filtering, non-authoritative JS status projection, and
fail-closed JS facades from terminal Rust daemon-core shape, and avoid encoding
command transport, canonical input helpers, or read-only JS helpers as
long-term substrate.
Slice 758 retired the public catalog-provider OAuth callback's retired
`oauth_state` and `oauthState` compatibility aliases before the Rust-core
required boundary. The fail-closed OAuth facade now preflights only the
OAuth-standard `state` callback field before rejecting at
`model_mount.catalog_provider_control`, so duplicate OAuth-state request shapes
can no longer satisfy the public catalog-provider control surface. This does
not claim terminal catalog-provider control migration: direct Rust daemon-core
catalog-provider control still needs to own OAuth state/session custody,
wallet/cTEE vault binding, auth-header refresh, receipts, Agentgres admission,
record-state, projection, and replay. The Slice 758 catalog-provider OAuth
callback state alias-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 759 retired catalog-provider runtime-material read-cache writes: the
remaining runtime-material read adapter no longer writes vault refs or caches
resolved, missing, or failed vault material into `catalogProviderRuntimeMaterials`.
This removes another local JS duplicate truth path while catalog-provider
configuration, OAuth, and auth-header mutation facades remain fail-closed at
`model_mount.catalog_provider_control`. This does not claim terminal
catalog-provider projection migration: direct Rust daemon-core catalog-provider
control/projection still needs to own runtime-material projection, wallet/cTEE
custody, receipts, Agentgres admission, record-state, replay, and conformance.
The Slice 759 catalog-provider runtime-material read-cache retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 760 retired catalog download policy request synonyms that were still
accepted as alternate canonical fields: `bandwidth_limit_bps`,
`resume_download`, `retries`, and `destructive_confirmed` can no longer steer
catalog transfer policy or destructive confirmation before the Rust-core
required boundary. The public facade now accepts only `bandwidth_bps`,
`retry_limit`, `resume`, `cleanup_partial`, `transfer_approved`, and
`confirm_destructive` for those helper decisions, while camelCase policy aliases
continue to fail closed. This does not claim terminal catalog/download
migration: direct Rust daemon-core catalog/download/filesystem/admission APIs
still need to own transfer policy admission, destructive action authority,
receipt binding, Agentgres admission, record-state, projection, replay, and
conformance. Do not encode the remaining JS helper as terminal architecture.
The Slice 760 catalog download policy request-synonym retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 761 retired remaining camelCase policy steering from model-mount route
selection: `denyFixtureModels` and `maxCostUsd` can no longer affect endpoint
selection before Rust model_mount route-decision admission. The selector now
honors only canonical `deny_fixture_models` and `max_cost_usd` alongside the
already canonical hosted-fallback policy. This does not claim terminal route
selection migration: direct Rust daemon-core model_mount route-control and
route-decision APIs still need to own route policy evaluation, authority gates,
receipt binding, Agentgres admission, projection, replay, and conformance.
Do not encode the remaining JS selector helper as terminal architecture.
The Slice 761 model-mount route-selection policy alias-retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 762 retired the hidden catalog-provider JS config-update helper that could
still bind source material, write vault refs, and synthesize catalog-provider
configuration records outside the public fail-closed Rust-core control facade.
`model-mounting.mjs` no longer imports or injects `catalogProviderConfigUpdate`,
and catalog-provider source material parsing now accepts only canonical
`manifest_path` and `base_url`; retired `path`, `url`, `manifestPath`, and
`baseUrl` inputs fail closed before vault binding. This does not claim terminal
catalog-provider control migration: direct Rust daemon-core catalog-provider
control/projection still needs to own configuration, OAuth state/session
custody, wallet/cTEE vault binding, auth-header refresh, receipts, Agentgres
admission, record-state, projection, replay, and conformance. Do not encode the
remaining JS source/auth helpers as terminal architecture.
The Slice 762 catalog-provider config-update helper retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 763 retired the hidden `ConversationArtifactStore` JS mutation writers
behind the already retired public conversation-artifact control facade. The
store no longer imports the JS artifact-state committer, materializes generated
artifact files, creates conversation-artifact receipts, writes accepted
conversation-artifact records, or exposes private `#receipt`/`#write` mutation
bodies. Direct `create`, `action`, `exportArtifact`, and `promoteArtifact`
calls now fail closed with `runtime_conversation_artifact_store_rust_core_required`
before JS file writes, record writes, receipt synthesis, or Agentgres artifact
state commits can occur. The remaining store is a read/projection adapter over
already-admitted canonical records only. This does not claim terminal
conversation-artifact migration: direct Rust daemon-core artifact admission and
projection still need to own lifecycle execution, receipt binding, ArtifactRef
and PayloadRef admission, Agentgres expected-head/state-root binding,
projection, replay, SDK/later stable client protocol rows, and conformance. Do not encode
the remaining JS read adapter as terminal architecture.
The Slice 763 direct conversation-artifact store writer retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 764 retired the hidden `AgentMemoryStore` JS mutation writers and
run-memory write/policy command mutation path behind the already fail-closed
public thread-memory control facade. `AgentMemoryStore` no longer receives a
`commitRuntimeMemoryState` injection from the runtime store and direct
`remember`, `updateRecord`, `deleteRecord`, `setPolicy`, `write`, `writePolicy`,
or `commitMemoryState` calls now fail closed with
`runtime_memory_state_store_rust_core_required` before JS record-map mutation,
policy-map mutation, local memory/policy file writes or deletes, receipt
synthesis, or memory-state commit transport can occur. Run-memory resolution
now requires the mounted thread-memory Rust projection/control surface for chat/API
remember, edit, delete, enable, and disable commands: it reads policy/path/record
truth through Rust public memory projection, commits write/edit/delete/policy
changes through Rust `plan_runtime_memory_control` plus Agentgres
memory-state admission, and fails closed before JS memory cache reads if that
surface is absent. Public thread/agent memory write, edit, delete, and
policy mutation have a positive Rust daemon-core boundary through
`plan_runtime_memory_control`, followed by Rust Agentgres memory-state commit
before route projection returns. The runtime memory event-control cut extends
that boundary to status, validation, and direct memory control-event append:
those event-only operations now use Rust `plan_runtime_memory_control` and Rust
runtime-event Agentgres admission instead of JS event authorship. The thread
memory transport cut now reaches memory projection/control, memory-manager
status/validation projection, and thread-memory agent state-update through
typed `daemonCoreThreadMemoryApi` methods, and Rust rejects the retired memory
command operations. This does not claim terminal memory migration: policy
authority, cTEE private-memory custody, broader receipt/state-root binding,
ArtifactRef/PayloadRef where needed, durable replay/projection storage, SDK/IDE
protocol coverage, and conformance still need direct ownership. Do not encode
the remaining JS memory adapters or run-memory projection helper as terminal
architecture.
The Slice 764 direct `AgentMemoryStore` writer and run-memory mutation path
retirement matrix-compaction pass is complete. No matrix-compaction pass is
pending until the next Rust-core extraction or facade-retirement seam lands.
Slice 765 retired the private backend registry local log writer behind
model-mount backend lifecycle migration plumbing. `writeBackendLog()` no longer
imports filesystem APIs, creates `backend-logs/*.jsonl`, mirrors endpoint logs
to backend-specific files, or lets backend process supervision create a local
log truth path outside Rust daemon-core lifecycle/projection ownership. The
helper now returns redacted non-persistent telemetry marked with
`model_mount_backend_log_js_writer_retired`, while public backend
health/start/stop/log facades remain fail-closed at the Rust-core-required
boundary. This does not claim terminal backend lifecycle migration: direct Rust
daemon-core backend lifecycle/control/projection still needs to own process
control, log/event projection, Agentgres expected-head/state-root binding,
receipt/event materialization, replay, SDK/later stable client protocol rows, and
conformance. Do not encode the remaining JS process-supervision helper as
terminal architecture.
The Slice 765 backend registry local log writer retirement matrix-compaction
pass is complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 766 retired the stale `ConversationArtifactStore` artifact-state
committer injection. The runtime store now mounts
`new ConversationArtifactStore(this.stateDir)` without a
`commitRuntimeArtifactState` option, and the store no longer keeps a
`commitRuntimeArtifactState` property. Direct artifact mutation methods were
already fail-closed from Slice 763; this slice removes the remaining
writer-shaped constructor surface so the conversation-artifact read/projection
adapter cannot appear to forward accepted artifact truth through JS. This does
not claim terminal conversation-artifact migration: direct Rust daemon-core
artifact admission/projection still needs to own lifecycle execution, receipt
binding, ArtifactRef/PayloadRef admission, Agentgres expected-head/state-root
binding, projection, replay, SDK/later stable client protocol rows, and conformance. Do not
encode the remaining JS read adapter or artifact-state command transport as
terminal architecture.
The Slice 766 conversation-artifact committer injection retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 767 retired remaining MCP manager/catalog/helper camelCase config/source
handoffs that kept compatibility-shaped fields inside the JS projection/control
adapter. The
runtime MCP catalog surface now passes `mcp_config_source_mode`,
`workspace_root`, `source_scope`, and `config_compatibility` into the manager
normalizer; MCP mutation/add helpers pass canonical `workspace_root` and
`source_scope`; `mcp-manager.mjs` no longer consumes `sourcePath`,
`sourceScope`, or `configCompatibility` from server config or context and no
longer includes retired context source/config aliases in evidence refs. This
does not claim terminal MCP migration: direct
Rust daemon-core MCP control/admission/projection still needs to own registry
truth, external-exit authority, transport containment, receipts, Agentgres
expected-head/state-root binding, replay, SDK/later stable client protocol rows, and
conformance. Do not encode the remaining JS MCP read/config helpers or command
transport as terminal architecture.
The Slice 767 MCP manager/catalog/helper config/source handoff alias-retirement
matrix-compaction pass is complete.
Slice 768 retired visual observation artifact materialization path alias
fallback metadata in the coding-tool artifact mutation fail-closed surface.
`runtime-coding-tool-artifact-surface.mjs` now derives
`has_screenshot_path`, `has_som_path`, and `has_ax_path` only from canonical
`screenshot_path`, `som_path`, and `ax_path`; retired `screenshotPath`,
`somPath`, and `axPath` inputs no longer count as local path presence and do
not appear in fail-closed error details. This does not claim terminal visual
artifact migration: direct Rust daemon-core coding-tool artifact admission still
needs to own visual artifact materialization, receipt binding,
ArtifactRef/PayloadRef admission, Agentgres expected-head/state-root binding,
projection, replay, SDK/later stable client protocol rows, and conformance. Do not encode
the remaining fail-closed JS artifact facade as terminal architecture.
The Slice 768 visual artifact path alias-retirement matrix-compaction pass is
complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 769 retired the MCP serve `tools/call` `params.args` fallback before
served runtime tool invocation input crosses into the daemon: at that slice,
the MCP serve surface consumes canonical MCP `params.arguments` only. Slice 955
later retired the remaining MCP serve JS tool-call dispatch path entirely.
Slice 1224 replaces the remaining MCP serve command transport with typed
`daemonCoreMcpApi.planRuntimeMcpServeToolCall` and
`daemonCoreMcpApi.projectRuntimeMcpServeToolResult`, backed by Rust
`RuntimeKernelService::plan_runtime_mcp_serve_tool_call` and
`RuntimeKernelService::project_runtime_mcp_serve_tool_result`; canonical
`params.arguments` now crosses only as Rust planner input before the adapter
calls the Rust-owned coding-tool invocation surface. Slice 1236 then binds MCP
serve `tools/call` public return to Rust-authored Agentgres live-result truth:
Rust `project_runtime_mcp_serve_tool_result` now emits a materialized
`ioi.runtime.mcp-live-result.v1` record with the protocol result payload,
receipt refs, `runtime.mcp_serve` result authorship, and no retired JS/command/
binary-bridge/compatibility fallback proof fields; the JS adapter must
`commitRuntimeMcpLiveResultState()` and `projectMcpLiveResultReplay()` before it
can wrap the replayed protocol payload as JSON-RPC. This does not claim terminal
MCP serve migration: external Rust MCP transport execution, transport
containment for non-coding-tool live backends, SDK/later stable client protocol rows, and
conformance still require deeper Rust ownership.
Do not encode the remaining JS MCP serve protocol facade as terminal
architecture. The Slice 769 MCP serve `params.args` alias-retirement
matrix-compaction pass is complete, and the Slice 1224/1236 MCP serve
authority-boundary cuts are tracked in the macro authority ledger.
Slice 1237 then hard-cuts hosted provider lifecycle/inventory metadata transport
out of the refusal-marker lane: Rust now emits contained hosted metadata
transport contracts with `rust_materialized` execution status, cTEE
no-plaintext custody evidence, wallet.network transport authority evidence, and
no retired JS/command/binary-bridge/compatibility fallback proof fields, while the
JS protocol edge rejects retired `hosted_provider_transport_not_executed`
evidence before public truth can return.
Slice 770 retired the MCP manager `allowedTools` server config/catalog fallback
before MCP manager records can expose tools. `mcp-manager.mjs` now derives
declared tool exposure only from canonical `allowed_tools` and declared `tools`
object keys; retired `allowedTools` can no longer create catalog tool records or
suppress empty-allowed-tools warnings. This does not claim terminal MCP manager
migration: direct Rust daemon-core MCP control/admission/projection still needs
to own wallet authority, transport containment, StepModuleRouter dispatch,
receipt binding, Agentgres expected-head/state-root binding, registry truth,
replay, SDK/later stable client protocol rows, and conformance. Do not encode the remaining
JS MCP manager/catalog helpers as terminal architecture. The Slice 770 MCP
manager `allowedTools` alias-retirement matrix-compaction pass is complete.
Slice 771 retired the MCP manager `allowedResources` and `allowedPrompts`
server config/catalog fallbacks before MCP manager resource/prompt records can
be exposed. `mcp-manager.mjs` now derives resource and prompt catalog exposure
only from canonical `resources`, `prompts`, `allowed_resources`, or
`allowed_prompts`; retired camelCase aliases can no longer create resource or
prompt catalog rows or registry counts. This does not claim terminal MCP manager
migration: direct Rust daemon-core MCP control/admission/projection still needs
to own wallet authority, transport containment, StepModuleRouter dispatch,
receipt binding, Agentgres expected-head/state-root binding, registry truth,
replay, SDK/later stable client protocol rows, and conformance. Do not encode the remaining
JS MCP manager/catalog helpers as terminal architecture. The Slice 771 MCP
manager resource/prompt alias-retirement matrix-compaction pass is complete.
Slice 772 retired MCP manager `serverUrl`, `containmentMode`,
`allowNetworkEgress`, and `allowChildProcesses` transport/containment
fallbacks. `mcp-manager.mjs` now derives remote MCP URLs from canonical
`server_url`, `url`, or `endpoint` only and derives containment policy from
canonical snake_case fields only, so retired camelCase aliases can no longer
satisfy HTTP/SSE URL validation or loosen network/child-process containment
policy. This does not claim terminal MCP manager migration: direct Rust
daemon-core MCP control/admission/projection still needs to own wallet
authority, transport containment, StepModuleRouter dispatch, receipt binding,
Agentgres expected-head/state-root binding, registry truth, replay, SDK/IDE
protocol coverage, and conformance. Do not encode the remaining JS MCP
manager/catalog helpers as terminal architecture. The Slice 772 MCP manager
transport/containment alias-retirement matrix-compaction pass is complete.
Slice 773 retired the MCP manager validation `secretRefs` fallback. MCP manager
validation now reads only canonical `secret_refs`, so retired camelCase
`secretRefs` can no longer feed vault-ref validation, satisfy or suppress
`mcp_secret_not_vault_ref` diagnostics, or create duplicate secret truth at the
manager validation boundary. This does not claim terminal MCP manager migration:
direct Rust daemon-core MCP control/admission/projection still needs to own
wallet authority, transport containment, StepModuleRouter dispatch, receipt
binding, Agentgres expected-head/state-root binding, registry truth, replay,
SDK/later stable client protocol rows, and conformance. Do not encode the remaining JS MCP
manager/catalog helpers as terminal architecture. The Slice 773 MCP manager
validation secret-ref alias-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 774 moved public MCP server validation decisioning into Rust daemon-core
validation transport. `McpServerValidationCore` now owns validation status,
diagnostics, and warnings for normalized canonical MCP server records, the
daemon-core command bridge exposes `validate_mcp_servers`, and the runtime
daemon `validateMcp()` facade consumes `contextPolicyCore.validateMcpServers`
instead of synthesizing public validation pass/block truth in JS. This remains
migration transport, not the terminal direct daemon-core API: catalog
normalization/projection and manager/status helpers still need direct Rust
MCP control/admission/projection ownership before terminal migration is claimed.
The Slice 774 MCP server validation Rust-core matrix-compaction pass is complete.
No matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 775 retired the public MCP status JS validation decision path. The runtime
MCP catalog surface no longer imports or injects `validateMcpServerRecords`;
both `mcpStatus()` and `validateMcp()` now send normalized canonical server
records through `contextPolicyCore.validateMcpServers({ servers })` so public
MCP status/validation pass-block decisions come from Rust
`McpServerValidationCore` via `validate_mcp_servers` migration transport. This
still does not claim terminal MCP migration: catalog normalization/projection,
registry truth, wallet authority, transport containment, receipt binding,
Agentgres admission, replay, and SDK/later stable client protocol rows still need direct
Rust daemon-core ownership. The Slice 775 MCP status validation Rust-core
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 776 moved public MCP status readiness/count/projection into Rust
daemon-core migration transport. `McpManagerStatusProjectionCore` now owns the
public `mcpStatus()` readiness, server/tool/resource/prompt counts,
enabled-server counts, validation embedding, route projection, and canonical
snake_case status envelope through `plan_mcp_manager_status_projection`; the JS
catalog surface still gathers normalized catalog rows as migration adapter input
but no longer derives the public status/count envelope itself. This still does
not claim terminal MCP migration: direct Rust daemon-core MCP registry truth,
catalog gathering, wallet authority, transport containment, StepModuleRouter
dispatch, receipt binding, Agentgres admission, replay, and SDK/IDE protocol
coverage still need direct Rust daemon-core ownership. The Slice 776 MCP status
projection Rust-core matrix-compaction pass is complete. No matrix-compaction
pass is pending until the next Rust-core extraction or facade-retirement seam
lands.
Slice 777 routed agent-scoped MCP status validation and projection through Rust
daemon-core migration transport. `mcpStatusForAgent()` no longer imports,
injects, or calls the JS `validateMcpServerRecords` validator and no longer
derives readiness/count projection itself; it sends canonical agent MCP server
records through `validate_mcp_servers` and the status envelope through
`plan_mcp_manager_status_projection`, with `McpManagerStatusProjectionCore`
owning optional `enabled_tool_count` for agent-scoped status. This still does
not claim terminal MCP migration: direct Rust daemon-core MCP registry truth,
catalog gathering, wallet authority, transport containment, StepModuleRouter
dispatch, receipt binding, Agentgres admission, replay, and SDK/IDE protocol
coverage still need direct Rust daemon-core ownership. The Slice 777
agent-scoped MCP status Rust-core matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 778 moved MCP status catalog-row projection into Rust daemon-core
migration transport. `McpManagerCatalogProjectionCore` now derives the
tool/resource/prompt/enabled-tool rows consumed by both public `mcpStatus()` and
agent-scoped `mcpStatusForAgent()` before those rows enter
`McpManagerStatusProjectionCore`; the JS status surfaces no longer call
`mcpToolsForServers`, resource sorting, or prompt sorting as the
readiness/count/status input authority. This still does not claim terminal MCP
migration: direct Rust daemon-core MCP registry truth, live transport
containment, wallet authority, StepModuleRouter dispatch, receipt binding,
Agentgres admission, replay, and SDK/later stable client protocol rows still need direct
Rust daemon-core ownership. The Slice 778 MCP status catalog-projection
Rust-core matrix-compaction pass is complete. No matrix-compaction pass is
pending until the next Rust-core extraction or facade-retirement seam lands.
Slice 779 moved public MCP validation envelope projection into Rust daemon-core
migration transport. At that slice, `validateMcp()` still parsed canonical
validation input in the JS facade during migration, but sent canonical server
records through `validate_mcp_servers`, derived validation catalog rows through
`plan_mcp_manager_catalog_projection`, and returns the public validation
envelope through `McpManagerValidationProjectionCore` /
`plan_mcp_manager_validation_projection`; the JS facade no longer derives the
public validation status, counts, issues/warnings counts, or tool/resource/prompt
row envelope itself. This still does not claim terminal MCP migration: direct
Rust daemon-core MCP registry truth, live transport containment, wallet
authority, StepModuleRouter dispatch, receipt binding, Agentgres admission,
replay, and SDK/later stable client protocol rows still need direct Rust daemon-core
ownership. The Slice 779 MCP validation projection Rust-core matrix-compaction
pass is complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 780 moved public MCP declared catalog list/search row projection into Rust
daemon-core migration transport. `listMcpTools()`, `listMcpResources()`,
`listMcpPrompts()`, and declared-catalog `searchMcpToolCatalog()` now consume
`McpManagerCatalogProjectionCore` / `plan_mcp_manager_catalog_projection`
instead of calling JS `mcpToolsForServers`, `mcpResourcesForServers`, or
`mcpPromptsForServers` row builders; later Slice 783 removes the JS live
discovery transport path so catalog search/fetch remains on Rust-projected
declared rows until a Rust MCP transport backend owns live discovery.
This still does not claim terminal MCP migration: direct Rust daemon-core MCP
registry truth, live transport discovery and containment, wallet authority,
StepModuleRouter dispatch, receipt binding, Agentgres admission, replay, and
SDK/later stable client protocol rows still need direct Rust daemon-core ownership. The
Slice 780 MCP public catalog Rust-core matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 781 moved MCP catalog summary projection into Rust daemon-core migration
transport. `searchMcpToolCatalog()` now passes declared tool/resource/prompt
rows through `McpManagerCatalogSummaryProjectionCore` /
`plan_mcp_manager_catalog_summary_projection` before public search/fetch
responses expose `ioi.runtime_mcp_catalog_summary` records; the JS catalog
surface no longer imports, injects, or calls `mcpCatalogSummaryForServer()` for
those public summaries. This still does not claim terminal MCP migration:
direct Rust daemon-core MCP registry truth, live transport discovery and
containment, wallet authority, StepModuleRouter dispatch, receipt binding,
Agentgres admission, replay, and SDK/later stable client protocol rows still need direct
Rust daemon-core ownership. The Slice 781 MCP catalog summary Rust-core
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands.
Slice 782 retired the dead helper-level JS MCP catalog summary/exposure path.
`runtime-mcp-helpers.mjs` no longer exports `mcpCatalogSummaryForServer()`,
`mcpCatalogExposureForStatus()`, or `mcpToolNamespaces()`; helper tests no
longer preserve the old JS summary hash/namespace implementation as a
self-referential compatibility surface. Public MCP summary projection remains
owned by `McpManagerCatalogSummaryProjectionCore` through migration transport.
This still does not claim terminal MCP migration: direct Rust daemon-core MCP
registry truth, live transport discovery and containment, wallet authority,
StepModuleRouter dispatch, receipt binding, Agentgres admission, replay, and
SDK/later stable client protocol rows still need direct Rust daemon-core ownership. The
Slice 782 MCP helper summary-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.

Slice 783 retires the JS MCP catalog live-discovery and thread-agent catalog
truth path. `McpManagerCatalogProjectionRequest` now carries runtime
`state_dir`, `thread_id`, and `agent_id`; `McpManagerCatalogProjectionCore`
replays admitted `agents/*.json` Agentgres records before returning contextual
server/tool/resource/prompt rows, and rejects JS-supplied `agent` candidate
transport. The runtime MCP catalog surface no longer calls `agentForThread()`,
`store.agents`, `store.getAgent()`, `discoverMcpStdioCatalog()`, or
`discoverMcpHttpCatalog()`; `mcp-manager.mjs` no longer exports JS stdio/HTTP
catalog discovery or tool invocation helpers. Public catalog live-discovery
requests now return Rust-projected declared rows with a
`rust_mcp_live_discovery_materialized` summary instead of executing JS
transport or preserving the old deferred marker.
This still does not claim terminal MCP migration: actual Rust MCP transport
execution, StepModuleRouter live backend execution, replay/projection storage,
and stable SDK/IDE protocol APIs remain non-terminal.
Slice 783 retired the dead helper-level JS MCP mutation/registry projection
path. `runtime-mcp-helpers.mjs` no longer exports
`mcpRegistryWithServers()`, `mcpServerRecordsFromMutationInput()`,
`mcpServerRecordFromAddRequest()`, `mcpResourceKey()`, or `mcpPromptKey()`;
helper tests no longer preserve those JS import/add/registry projection bodies
after MCP control mutation helper projection became non-authoritative and
validation/catalog projection routes through Rust daemon-core migration
transport. This still does
not claim terminal MCP migration: direct Rust daemon-core MCP registry truth,
live transport discovery and containment, wallet authority, StepModuleRouter
dispatch, receipt binding, Agentgres admission, replay, and SDK/IDE protocol
coverage still need direct Rust daemon-core ownership. The Slice 783 MCP helper
mutation/registry-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 784 moved MCP validation-input parsing into Rust daemon-core migration
transport. `McpServerValidationInputCore` /
`project_mcp_server_validation_input` now owns canonical raw `mcp_json` /
`mcp_servers` normalization into snake_case MCP server records before
`validate_mcp_servers`; `mcpServerRecordsFromValidationInput()` remains only a
JS transport wrapper around `contextPolicyCore.projectMcpServerValidationInput`
and no longer walks raw validation JSON itself. This still does not claim
terminal MCP migration: direct Rust daemon-core MCP registry truth, live
transport discovery and containment, wallet authority, StepModuleRouter
dispatch, receipt binding, Agentgres admission, replay, and SDK/IDE protocol
coverage still need direct Rust daemon-core ownership. The Slice 784 MCP
validation-input Rust-core matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 785 retired the remaining helper-level JS MCP validation decision path.
`mcp-manager.mjs` no longer exports `validateMcpServerRecords()` or the
`RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION` helper constant, and focused
MCP manager tests no longer preserve local JS validation diagnostics after
public status/validation already route through Rust `McpServerValidationCore`.
This still does not claim terminal MCP migration: direct Rust daemon-core MCP
registry truth, live transport discovery and containment, wallet authority,
StepModuleRouter dispatch, receipt binding, Agentgres admission, replay, and
SDK/later stable client protocol rows still need direct Rust daemon-core ownership. The
Slice 785 MCP JS validation helper-retirement matrix-compaction pass is
complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 786 moved public memory manager status and validation projection into the
Rust daemon-core migration transport. `MemoryManagerStatusProjectionCore` and
`MemoryManagerValidationProjectionCore` now own canonical
`ioi.runtime_memory_manager_status` / `ioi.runtime_memory_manager_validation`
envelopes, while `memoryStatusForProjection()` and
`validateMemoryProjection()` remain only thin JS transport wrappers around
`contextPolicyCore.planMemoryManagerStatusProjection()` /
`planMemoryManagerValidationProjection()`. Public memory status/validate routes
therefore no longer calculate readiness, issue counts, memory-key counts,
write-block reasons, routes, validation records, or evidence refs in JS. This
still does not claim terminal memory migration: direct Rust daemon-core memory
record truth, Agentgres admission/head/state-root binding, wallet authority,
StepModuleRouter dispatch for admitted memory work, cTEE custody coupling,
replay, SDK/later stable client protocol rows, and direct Rust API replacement for command
transport still need ownership. The Slice 786 memory manager projection
Rust-core matrix-compaction pass is complete. No matrix-compaction pass is
pending until the next Rust-core extraction or facade-retirement seam lands; do
not encode the command bridge or JS transport wrappers as terminal
architecture.
The current runtime-memory macro cut extends that boundary from status and
validation envelopes to the route-facing public memory read family. Public
memory list, policy, path, status, and validation now call Rust
`project_runtime_memory_projection` through the mounted thread-memory surface;
JS supplies only canonical context, filters, and runtime `state_dir`; Rust
replays admitted `memory-records/*.json` and `memory-policies/*.json`, rejects
retired projection candidate transport, and fails closed when the Rust projector
is absent or returns a mismatched projection kind. Public memory mutation now
sends runtime `state_dir`; Rust replays admitted current record/policy truth and
rejects JS `current_record`/`current_policy` transport. Wallet authority, direct
admission/storage APIs, stable protocol APIs, and
cTEE-coupled private workspace custody remain non-terminal.
The current conversation-artifact read/control macro cut replaces the
fail-closed public read facade and the mutation-only refusal facade with Rust
daemon-core projection and control planning. Public and thread-scoped
conversation-artifact list, get, and revision-list routes call
`project_runtime_conversation_artifact_projection` through the mounted
conversation-artifact surface, while create/action/export/promote call
`plan_runtime_conversation_artifact_control` and commit only the Rust-authored
artifact through Rust Agentgres artifact-state admission. Read projection and
action/export/promote control send canonical request fields plus runtime
`state_dir`; Rust replays admitted `artifacts/*.json` conversation-artifact
records before returning route truth and rejects retired JS artifact candidate
transport. The route family fails closed when Rust projection, planning, replay,
or commit is absent or mismatched. Durable ArtifactRef/PayloadRef truth, richer
Agentgres mutation replay/projection storage,
wallet/cTEE authority where needed, receipt/state-root binding, and direct
protocol APIs remain non-terminal.
The current subagent read macro cut replaces the fail-closed public subagent
read facade with Rust daemon-core projection. Public subagent list, get, and
result routes now call `project_runtime_subagent_projection` through the
mounted subagent surface with runtime `state_dir`; Rust replays admitted
`subagents/*.json` and `runs/*.json` Agentgres records before route truth can
return, owns parent-thread filtering, role filtering, subagent id selection,
result envelope shaping, projection-kind validation, evidence refs, and receipt
refs, and rejects retired JS subagent/run candidate transport. The route family
fails closed when the Rust projector or `state_dir` replay is absent or
mismatched. Subagent mutation/admission, StepModuleRouter delegation
authority, wallet delegation/cancellation authority, durable Agentgres
storage/replay, receipt/state-root binding, and direct protocol APIs remain
non-terminal.
The current subagent wait-control macro cut replaces the wait fail-closed JS
facade with Rust daemon-core control planning. Public `waitSubagent()` now calls
`plan_runtime_subagent_control` for the `subagent.wait` lifecycle event, admits
the Rust-authored event through the Rust runtime-event Agentgres path, calls the
Rust subagent record state-update planner, and persists only the Rust-planned
subagent projection through Agentgres-backed `writeSubagent`. The direct
subagent assignment/cancellation macro cut extends that Rust control boundary to
`subagent.assign` and `subagent.cancel`; assignment now requires Rust control
planning, Rust runtime-event Agentgres admission, Rust subagent state-update
planning, and Agentgres-backed `writeSubagent`, while cancellation first enters
the Rust run-cancel state-update path and then commits the Rust-planned subagent
cancellation projection. The subagent input/resume macro cut extends the same
boundary to `subagent.input` and `subagent.resume`; both controls now require
the Rust read projection, Rust-owned child-agent run creation through the
direct lifecycle run-create API, Rust control planning, Rust runtime-event Agentgres
admission, Rust subagent state-update planning, and Agentgres-backed
`writeSubagent` persistence. The subagent spawn macro cut extends the boundary
to `subagent.spawn`; public `spawnSubagent()` now preflights the Rust subagent
control/state planner, composes Rust-owned child-agent creation and Rust-owned
child-run creation through direct lifecycle APIs, admits the
Rust-authored `subagent.spawned` runtime event, and persists only the
Rust-planned subagent projection through Agentgres-backed `writeSubagent`.
Cancellation propagation and direct control-event append now use Rust
control-event planning plus Rust runtime-event admission. StepModuleRouter
delegation/execution authority, wallet
delegation/cancellation authority, durable subagent replay/projection storage,
and direct protocol APIs remain non-terminal.
Slice 787 retired the memory projection input compatibility fallback at the
Rust boundary. `AgentMemoryStore.pathProjection()` now emits canonical
`records_path`, `policies_path`, and `effective_policy_id`, redacted memory
records use `fact_hash`, and `MemoryManagerStatusProjectionCore` /
`MemoryManagerValidationProjectionCore` read only canonical memory policy,
path, record, and evidence fields. Retired `injectionEnabled`, `readOnly`,
`writeRequiresApproval`, `subagentInheritance`, `recordsPath`, `policiesPath`,
`effectivePolicyId`, `memoryKey`, and `factHash` fields can no longer steer the
Rust memory status/validation projection. This still does not claim terminal
memory migration: direct Rust daemon-core memory record truth, Agentgres
admission/head/state-root binding, wallet authority, StepModuleRouter dispatch
for admitted memory work, cTEE custody coupling, replay, SDK/IDE protocol
coverage, and direct Rust API replacement for command transport still need
ownership. The Slice 787 memory projection input alias-retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands; do not encode the
command bridge or JS transport wrappers as terminal architecture.
Slice 788 retired the memory projection envelope identity aliases that still
fed JS-wrapped Rust memory status/validation calls. `AgentMemoryStore.projection()`
now emits canonical `schema_version`, `thread_id`, `agent_id`, and
`total_matches`, and `thread-memory-state` forwards only `projection.thread_id`
and `projection.agent_id` into the Rust-backed memory status/validation
projection wrappers. Retired top-level `schemaVersion`, `threadId`, `agentId`,
and `totalMatches` fields can no longer appear on the memory projection
envelope or steer status/validation identity. This still does not claim
terminal memory migration: direct Rust daemon-core memory record truth,
Agentgres admission/head/state-root binding, wallet authority, StepModuleRouter
dispatch for admitted memory work, cTEE custody coupling, replay, SDK/IDE
protocol coverage, and direct Rust API replacement for command transport still
need ownership. The Slice 788 memory projection envelope alias-retirement
matrix-compaction pass is complete. No matrix-compaction pass is pending until
the next Rust-core extraction or facade-retirement seam lands; do not encode the
command bridge or JS transport wrappers as terminal architecture.
Slice 789 retired the SDK memory output compatibility surface that still
advertised the pre-canonical projection, path, record, and policy field names.
`AgentMemoryProjection`, `AgentMemoryPathProjection`, `AgentMemoryRecord`, and
`AgentMemoryPolicy` now expose canonical snake_case response fields matching the
daemon/Rust memory projection boundary: `schema_version`, `thread_id`,
`agent_id`, `total_matches`, `records_path`, `policies_path`,
`effective_policy_id`, `fact_hash`, `memory_key`, workflow identity, timestamps,
evidence refs, policy target identity, and policy booleans. Retired SDK output
fields such as `schemaVersion`, `threadId`, `agentId`, `totalMatches`,
`recordsPath`, `effectivePolicyId`, `factHash`, `memoryKey`,
`workflowNodeId`, `createdAt`, `targetType`, `injectionEnabled`,
`writeRequiresApproval`, `subagentInheritance`, and `policyRefs` are no longer
part of the SDK memory output contract. This still does not claim terminal
memory migration: direct Rust daemon-core memory record truth, Agentgres
admission/head/state-root binding, wallet authority, StepModuleRouter dispatch
for admitted memory work, cTEE custody coupling, replay, and direct Rust API
replacement for command transport still need ownership. The Slice 789 SDK
memory output alias-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands; do not encode the command bridge or JS transport
wrappers as terminal architecture.
Slice 790 retired the public model-capability protocol output aliases that
still advertised the pre-canonical model_mount contract shape to SDK/API
consumers. `modelCapabilities()` and `ModelCapabilityContract` now expose
canonical snake_case response fields for capability identity, route identity,
authority requirements, policy target, provider priority, fallback policy,
fallback evidence, cost visibility, credential/vault readiness, receipt
behavior, workflow/agent availability, and candidate readiness. Retired output
fields such as `schemaVersion`, `routeId`, `modelRole`,
`primitiveCapability`, `authorityScopeRequirements`, `policyTarget`,
`privacyTier`, `providerPriority`, `fallbackPolicy`, `fallbackEvidence`,
`costEstimateVisibility`, `credentialReadiness`, `vaultReadiness`,
`byokRequired`, `receiptBehavior`, `workflowAvailability`,
`agentAvailability`, `endpointId`, `providerId`, `vaultRequired`, and
`evidenceRefs` are no longer part of the daemon or SDK model-capability
protocol contract. This still does not claim terminal model_mount migration:
direct Rust daemon-core route-control/projection APIs, Agentgres-admitted route
truth, wallet authority binding, StepModuleRouter dispatch, replay, and direct
Rust API replacement for command transport still need ownership. The Slice 790
model-capability protocol alias-retirement matrix-compaction pass is complete.
No matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands; do not encode the command bridge or JS transport
wrappers as terminal architecture.
Slice 791 moved route-selection receipt authoring out of the JS
model_mount facade and into the Rust daemon-core route-decision admission
boundary. `admit_model_mount_route_decision` now returns an
`accepted_receipt_record` authored by Rust from the admitted
`ModelMountRouteDecisionRecord`; the JS `routeSelectionReceipt()` path fails
closed unless that Rust-authored receipt is present, and the temporary
`receipt-operations.mjs` generic JS receipt-creation refusal was later
superseded by mounted receipt-authoring facade deletion. JS may still persist
the Rust-authored receipt through the existing Agentgres receipt-state commit gate,
but it no longer synthesizes the accepted `model_route_selection` receipt. This
still does not claim terminal model_mount migration: direct Rust daemon-core
route-control/projection APIs, Agentgres route truth beyond the current commit
gate, wallet authority binding, StepModuleRouter dispatch, replay, and direct
Rust API replacement for command transport still need ownership. The Slice 791
route-selection receipt Rust-authoring matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands; do not encode the command bridge or JS transport
wrappers as terminal architecture.
Slice 792 moved model_mount read-projection authoring out of the former JS
read-projection helper path and into Rust daemon-core projection
planning. `plan_model_mount_read_projection` now authors the canonical
model_mount projection, projection summary, route-decision projection, receipt
replay, and wallet authority snapshot envelopes through the Rust command
transport; the direct mounted state client prepares current state input, calls
`planReadProjection()`, and fails closed with
`model_mount_read_projection_rust_core_required` when Rust projection planning
is unavailable. This still does not claim terminal model_mount migration:
current state materialization and command transport remain migration plumbing,
and direct Rust daemon-core APIs still need to own storage-backed projection
reads, Agentgres projection watermarks, replay, wallet authority binding,
SDK/later stable client protocol rows, and replacement of the bridge process boundary. The
Slice 792 model_mount read-projection Rust-authoring matrix-compaction pass is
complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands; do not encode the command bridge,
JS transport wrappers, or local state materialization as terminal architecture.

Slice 793 moved canonical model_mount projection persistence behind the Rust
daemon-core projection plan. `writeProjection()` now requests
`canonicalProjectionWritePlan()` from the Rust read-projection planner and
`AgentgresModelMountingStore.writeProjection()` rejects direct JS projection
objects with `model_mount_projection_direct_write_forbidden` unless the write
carries the Rust projection source, backend, projection kind, and evidence refs.
This removes the direct `store.writeProjection("model-mounting-canonical",
this.projection())` path as an authoritative JS projection persistence seam.
This still does not claim terminal model_mount migration: JS still materializes
current state input and local projection files through migration transport, and
direct Rust daemon-core projection APIs over Agentgres-backed state still need
to replace the command boundary and local projection store. The Slice 793
model_mount projection-persistence Rust-plan matrix-compaction pass is
complete.

Slice 794 retired the store-level model_mount map writer that remained below
the state-level retired map persistence facade.
`AgentgresModelMountingStore.writeMap()` now fails closed with
`model_mount_store_map_write_retired` instead of writing local JSON records from
JS, so future callers cannot bypass the retired
`ModelMountingState.writeMap()`/`writeModelMountingMap()` guard. This still
does not claim terminal model_mount migration: JS still loads local
materialized records into in-memory maps as migration input, and direct Rust
daemon-core Agentgres read/materialization APIs still need to replace local JSON
map state. The Slice 794 model_mount store map-writer retirement
matrix-compaction pass is complete.

Slice 795 retired direct model_mount projection-cache reads and removed the
store adapter's local projection-store identity.
`AgentgresModelMountingStore.readProjection()` now fails closed with
`model_mount_projection_cache_read_retired` instead of reading local
`projections/*.json` cache files, and `adapterStatus()` now reports
`rust_plan_gated_receipt_projection_adapter` with evidence that Rust
daemon-core projection ownership is required. This still does not claim
terminal model_mount migration: canonical projections are still locally
materialized after Rust planning, JS still prepares state input for the planner,
and direct Rust daemon-core Agentgres projection/read APIs still need to replace
local cache files and command transport. The Slice 795 model_mount
projection-cache read retirement matrix-compaction pass is complete.

Slice 796 moved public model_mount projection-field list reads through the Rust
read-projection plan instead of returning direct JS-composed list arrays.
`listArtifacts()`, `listProviders()`, `listEndpoints()`, `listInstances()`,
`listRoutes()`, `listModelCapabilities()`, `listDownloads()`,
`listOAuthSessions()`, `listOAuthStates()`, and `listProviderHealth()` now read
their public arrays from `rustProjectionField()` over the canonical
`plan_model_mount_read_projection` projection. The JS read-model helpers remain
only as current-state input materializers for the migration planner. This still
does not claim terminal model_mount migration: direct Rust daemon-core
Agentgres-backed projection APIs still need to replace JS state materialization,
command transport, and local map/projection materialization; do not encode the
command bridge, JS transport wrappers, or local projection helpers as terminal
architecture.

Slice 797 moved the public model_mount snapshot envelope through the Rust
read-projection plan. `snapshot()` now requests projection kind `snapshot` from
`plan_model_mount_read_projection`, and the Rust bridge authors the snapshot
shape, its nested projection summary, workflow-node projection, adapter
boundaries, receipt tail, and public read arrays from canonical projection input
instead of calling the JS `modelMountingSnapshot()` helper from the facade. This
still does not claim terminal model_mount migration: JS still prepares current
state input for the planner, the command bridge remains migration transport, and
direct Rust daemon-core Agentgres projection APIs still need to replace local
map/projection materialization and JS transport wrappers.

Slice 798 moved public model_mount adapter-boundary and workflow-node binding
reads through Rust projection fields. `adapterBoundaries()` now returns the
Rust-authored `adapterBoundaries` projection object, and
`workflowNodeBindings()` now returns the Rust-authored `workflowBindings`
projection list. At this slice, the JS `buildAdapterBoundaries()` and
workflow-binding helper remained only as current-state input materializers for
the migration planner; Slice 816 later retired those dead helper exports. This
still does not claim terminal model_mount projection migration: JS still
prepares current state input, and direct Rust daemon-core Agentgres projection
APIs still need to replace command transport and local materialization.

Slice 799 moved successful latest model_mount provider-health and vault-health
read envelopes through Rust read-projection kinds. `latestProviderHealth()` now
preflights provider existence and health-record presence at the JS edge, then
returns the Rust-authored `latest_provider_health` projection. `latestVaultHealth()`
keeps its not-found edge check, then returns the Rust-authored
`latest_vault_health` projection. The returned health envelope, receipt replay,
and projection watermark now come from `plan_model_mount_read_projection` rather
than JS object construction. This still does not claim terminal model_mount
projection migration: JS still prepares current state input and not-found
translation, and direct Rust daemon-core Agentgres projection APIs still need to
replace command transport and local materialization.

Slice 800 retired the JS not-found preflight decisions from the latest
model_mount provider-health and vault-health read surfaces. `latestProviderHealth()`
now sends provider-scoped `latest_provider_health` projection requests directly
to `plan_model_mount_read_projection`; the Rust planner verifies provider
existence, health-record presence, and receipt binding before authoring or
rejecting the read. `latestVaultHealth()` now sends `latest_vault_health`
projection requests directly to the Rust planner, which verifies the vault
health receipt exists. The JS facade only translates Rust rejection codes such
as `model_mount_provider_not_found`, `model_mount_provider_health_not_found`,
and `model_mount_vault_health_not_found` into the existing public 404 envelope.
This still does not claim terminal model_mount projection migration: JS still
prepares current state input and command transport remains migration transport
until direct Rust daemon-core Agentgres projection APIs replace it.

Slice 801 retired the JS adapter-boundary object materializer from the
model_mount read-projection facade. `readProjectionInput()` no longer imports or
calls `buildAdapterBoundaries()` and no longer passes an `adapter_boundaries`
object into the Rust planner. Instead it passes primitive `wallet`, `vault`, and
`agentgres_store` adapter status inputs, and `plan_model_mount_read_projection`
authors the public `adapterBoundaries` projection object, including OAuth
boundary metadata, inside Rust. This still does not claim terminal model_mount
projection migration: JS still prepares broad current-state input and command
transport remains migration transport until direct Rust daemon-core Agentgres
projection APIs replace it.

Slice 802 retired the JS workflow-node binding materializer from the model_mount
read-projection facade. `readProjectionInput()` no longer imports or calls
`workflowNodeBindingsProjection()` and no longer passes a `workflow_bindings`
list into the Rust planner. `plan_model_mount_read_projection` now authors the
public `workflowBindings` and snapshot `workflowNodes` lists inside Rust,
including canonical node names, capability bindings, route, receipt, and daemon
API metadata. This still does not claim terminal model_mount projection
migration: JS still prepares broad current-state input and command transport
remains migration transport until direct Rust daemon-core Agentgres projection
APIs replace it.

Slice 803 retired the JS model-capability projection materializer from the
model_mount read-projection facade. `readProjectionInput()` no longer receives
or calls `buildModelCapabilities()` and no longer passes a `model_capabilities`
list into the Rust planner. `plan_model_mount_read_projection` now derives the
public `modelCapabilities` contract inside Rust from primitive route, endpoint,
provider, artifact, and loaded-instance projection inputs, including candidate
readiness, credential/vault posture, fallback evidence, policy target, and
workflow/agent availability. This still does not claim terminal model_mount
projection migration: JS still prepares broad current-state input and command
transport remains migration transport until direct Rust daemon-core Agentgres
projection APIs replace it.

Slice 804 retired the JS product-safe model-list materializers from the
model_mount read-projection facade. `runtimeModelCatalogList()`,
`openAiModelList()`, and `listProductArtifacts()` now request dedicated Rust
read-projection kinds (`runtime_model_catalog`, `open_ai_model_list`, and
`product_artifacts`) instead of calling JS `runtimeModelCatalogList`,
`openAiModelList`, or `productArtifactList` helpers. Those dedicated projection
kinds use slim primitive artifact plus product policy input so product model
listing does not require broad snapshot/projection state materialization. This
still does not claim terminal model_mount projection migration: JS still
materializes many broad projection inputs for other read surfaces and command
transport remains migration transport until direct Rust daemon-core Agentgres
projection APIs replace it.

Slice 805 moved the remaining public model_mount projection-field list reads
onto dedicated slim Rust read-projection kinds. `listArtifacts()`,
`listProviders()`, `listEndpoints()`, `listInstances()`, `listRoutes()`,
`listModelCapabilities()`, `listDownloads()`, `listOAuthSessions()`,
`listOAuthStates()`, and `listProviderHealth()` no longer request the broad
`projection` envelope through `rustProjectionField()`. They now call dedicated
Rust read-projection kinds (`artifacts`, `providers`, `endpoints`,
`instances`, `routes`, `model_capabilities`, `downloads`, `oauth_sessions`,
`oauth_states`, and `provider_health`) with only the primitive input required
for each list. This still does not claim terminal model_mount projection
migration: snapshot/projection, workflow/adapter, health envelope, runtime
engine, and other broad read surfaces still need direct Rust daemon-core
Agentgres projection APIs to replace remaining JS state materialization and
command transport.

Slice 806 moved public model_mount workflow binding and adapter-boundary reads
onto dedicated slim Rust read-projection kinds. `workflowNodeBindings()` now
requests `workflow_bindings` directly from `plan_model_mount_read_projection`
with no JS state payload, and `adapterBoundaries()` now requests
`adapter_boundaries` with only primitive `wallet`, `vault`, and
`agentgres_store` adapter status inputs. The legacy `rustProjectionField()` and
`rustProjectionObjectField()` helpers are retired from the facade, so these
public reads no longer unwrap fields from the broad `projection` envelope. This
still does not claim terminal model_mount projection migration:
snapshot/projection, runtime engine, receipt replay, health envelope, and other
broad read surfaces still need direct Rust daemon-core Agentgres projection APIs
to replace remaining JS state materialization and command transport.

Slice 807 slimmed additional Rust-authored model_mount read projections so they
no longer require broad snapshot/projection state materialization, and the later
receipt-replay authority cut superseded the old receipt-list transport.
`projectionSummary()`, `authoritySnapshot()`, `latestProviderHealth()`,
`latestVaultHealth()`, `latestRuntimeSurvey()`, `receiptReplay()`, and broad
`snapshot()`/`projection()` now send empty JS request state plus runtime
`state_dir` into `plan_model_mount_read_projection`; Rust replays admitted
`receipts/*.json` records through the shared receipt projection boundary and
fails closed when `state_dir` is missing. `modelRouteDecisions()` remains on its
own route-selection `state_dir` replay path, so JS receipt arrays cannot return
as route-decision truth either. This still does not claim terminal model_mount
projection migration: command transport, richer joins, and other broad read
surfaces still need direct Rust daemon-core Agentgres projection APIs to replace
remaining JS state materialization.

Slice 808 slimmed public model_mount receipt replay, and the current
receipt-replay authority cut now removes the remaining JS receipt/topology
transport. `receiptReplay()` sends only empty request state, `receipt_id`, and
runtime `state_dir` into `plan_model_mount_read_projection`; Rust builds the
lookup context from admitted `receipts/*.json` records and ignores any caller
`state.receipts` payload. Route, endpoint, instance, and provider enrichments
remain null until direct Rust daemon-core Agentgres topology joins own them.
This still does not claim terminal model_mount projection migration: command
transport and richer projection joins still need direct Rust daemon-core APIs.

Slice 809 retired the snapshot helper's internal full-projection rebuild.
`snapshot()` still requests the Rust `snapshot` read-projection kind, but
`model_mount_snapshot()` no longer calls `model_mount_projection(request)` just
to recover adapter boundaries and projection summary. It now authors the nested
summary through the Rust receipt projection boundary backed by runtime
`state_dir` replay and authors adapter boundaries directly through
`model_mount_adapter_boundaries()`.
This still does not claim terminal model_mount projection migration: full
`projection`, snapshot input materialization, runtime engine, and other broad
read surfaces still need direct Rust daemon-core Agentgres projection APIs to
replace remaining JS state materialization and command transport.

Slice 810 moved public model_mount runtime-engine read surfaces through
dedicated Rust read-projection kinds. `runtimePreference()`,
`runtimePreferenceForEndpoint()`, `runtimeEngineProfile()`,
`listRuntimeEngineProfiles()`, `runtimeDefaultLoadOptions()`,
`runtimeEngine()`, and `listRuntimeEngines()` now request
`runtime_preference`, `runtime_preference_for_endpoint`,
`runtime_engine_profiles`, `runtime_default_load_options`,
`runtime_engine_detail`, and `runtime_engines` from
`plan_model_mount_read_projection`. The JS facade still prepares primitive
backend/profile/preference/receipt input as migration transport, but public
runtime-engine detail not-found decisions are now authored by Rust through
`model_mount_runtime_engine_not_found` rather than a JS preflight. This still
does not claim terminal runtime-engine migration: direct Rust daemon-core
Agentgres runtime-engine preference/profile/projection APIs still need to
replace JS current-state materialization and command transport.

Slice 811 moved public model_mount latest runtime-survey readback through a
dedicated Rust read-projection kind. `latestRuntimeSurvey()` now requests
`latest_runtime_survey` from `plan_model_mount_read_projection`, and broad
projection/snapshot input uses an explicit `runtime_survey_default` migration
payload instead of recursively calling the public JS read facade. Rust now
authors the checked runtime-survey envelope from canonical snake_case
`runtime_survey` receipt details, or returns the explicit not-checked default
when no admitted survey receipt exists. Later runtime-survey capture work
superseded the fail-closed capture edge with Rust daemon-core
`plan_model_mount_runtime_survey`, Rust hardware capture, Agentgres
runtime-engine replay, and Rust Agentgres model_mount receipt-state commit.
This still does not claim terminal runtime-survey migration: richer runtime
materialization, stable direct APIs, projection persistence, and
command-transport retirement remain required.

Slice 812 moved public model_mount server-status readback through a dedicated
Rust read-projection kind. `serverStatus()` now requests `server_status` from
`plan_model_mount_read_projection`, and broad projection/snapshot input uses an
explicit server-status migration payload instead of recursively calling the
public JS read facade. Server-control start/stop/restart/log/event mutations
still fail closed. This still does not claim terminal server-control migration:
direct Rust daemon-core server-control/state/log/event/projection APIs still
need to own server status, control state, log/event replay, Agentgres admission,
record-state, and command-transport retirement.

Slice 813 retired the JS-authored public server-status envelope from the
model_mount read-projection path. The runtime-daemon now sends only primitive
`server_status_input` migration data, and Rust authors the public
`server_status` projection plus nested snapshot and authority-snapshot `server`
objects through a shared planner helper. This still does not claim terminal
server-control migration: direct Rust daemon-core server-control/state/log/event
APIs still need to replace JS volatile-state collection and command transport.
Slice 1006 later retired that intermediate `server_status_input` transport:
Rust now authors the public `server_status` projection from empty request state
plus request-level `base_url`, and direct Rust server-control/state/log/event
projection APIs still need to replace the remaining command transport and
Agentgres-backed server truth gaps.

Slice 814 retired the JS-authored latest runtime-survey public envelope from
the model_mount read-projection path. The runtime-daemon sends primitive
`runtime_survey_input` migration data only for the dedicated
`latest_runtime_survey` read projection, and Rust authors the not-checked
fallback plus checked receipt projection through the shared read-projection
planner. Later runtime-survey capture work replaced the public fail-closed
capture edge with Rust `plan_model_mount_runtime_survey` and Rust Agentgres
model_mount receipt-state commit. This still does not claim terminal
runtime-survey migration: richer runtime materialization, stable direct APIs,
projection persistence, and command-transport retirement remain required.

Slice 815 retired the JS-authored catalog-status public envelope from
the model_mount read-projection path. The public `catalogStatus()` now requests
`catalog_status` from `plan_model_mount_read_projection`; in that slice the
runtime-daemon still sent primitive `catalog_status_input` migration data, and
the bridge authored the public catalog-status projection plus nested
snapshot/projection `catalog` objects through the shared read-projection
planner. Later facade-retirement work moved this surface past the intermediary
input transport. This still does not claim terminal catalog migration: direct
Rust daemon-core catalog/provider/search, download, Agentgres admission,
projection persistence, and command-transport retirement remain required before
catalog control and readback reach terminal unification.

Slice 816 retired the remaining dead JS model_mount broad projection helper
exports after their public callers had moved to Rust read-projection kinds.
`modelMountingSnapshot()` was removed from `read-model.mjs`; `workflowNodeBindings()`
was removed from that same legacy read helper module; and `buildModelMountingProjection()`,
`buildAuthoritySnapshot()`, `buildProjectionSummary()`,
`buildAdapterBoundaries()`, and `buildReceiptReplay()` were removed from
`projections.mjs`. `projections.mjs` now retains only the narrow
`buildModelRouteDecisions()` admitted-receipt projection helper used by
canonical route-decision checks. This still does not claim terminal model_mount
projection migration: the daemon still prepares local current-state input for
Rust projection transport until direct Rust daemon-core Agentgres projection APIs
replace JS state materialization and command transport.

Slice 817 retired that final dead `projections.mjs` compatibility surface
instead of preserving a one-helper projection module. The remaining public
model_route_decision reads continue through `modelRouteDecisions()` on the
read-projection facade, which calls Rust `plan_model_mount_read_projection`
kind `model_route_decisions` with admitted receipts as migration input.
`packages/runtime-daemon/src/model-mounting/projections.mjs` and its self-test
were deleted, and conformance now requires those files to remain absent. This
kept only a temporary route-decision receipt projection helper for live
route/thread binding until the next facade-retirement cut removed that helper
module entirely.

Slice 818 retired JS model-route decision authoring from route selection.
`createModelRouteDecision()` and its local policy/rationale/hash construction
helpers were removed from `route-decision.mjs`; route selection now builds only
the Rust `admit_model_mount_route_decision` request and uses a receipt-bound
`model_route_decision:${receipt_id}` idempotency key. The remaining route
selection and route-decision workflow request helpers now use canonical
snake_case transport fields instead of camelCase compatibility shapes. This
still does not claim terminal model_route migration: direct Rust daemon-core
route-control, route-selection, provider request shaping, projection, and
Agentgres-backed read APIs still need to replace JS helper transport and the
temporary bridge command path.

Slice 819 deleted the remaining `route-decision.mjs` compatibility module and
its self-test. At that point the tiny `model=auto` selector moved beside route
selection in `routes.mjs`; Slice 886 later deleted that JS selector as
migration-only scaffolding. The thread model-route binding reads canonical
`details.model_route_decision` locally and emits canonical `receipt_id` without
a `receiptId` alias; and the unused provider request-shaping helper/test path
is gone instead of being preserved as compatibility scaffolding. This still
does not claim terminal model_route migration: direct Rust daemon-core
route-control, route-selection, provider execution/request shaping, projection,
Agentgres-backed read APIs, and command-transport retirement remain required.

Slice 820 retired the provider-invocation helper-level false predicate for
hosted/non-migrated providers as an intermediate fail-closed cut. That
transitional JS predicate surface is now superseded by the Rust invocation
authority planner and the Slice 1382 helper-export deletion: provider invocation
request shape and stream request shape are Rust-authored, and the production JS
hot path no longer exposes helper predicates as a compatibility surface. This
still does not claim terminal provider migration: direct Rust daemon-core
hosted/provider transports, projection, Agentgres-backed reads, and
command-transport retirement remain required.

Slice 821 retired hosted/non-migrated provider-result observation admission
from the JS helper path as an intermediate fail-closed cut. That transitional
provider-result builder is now superseded by Rust
`provider_result_admission_request` planning in
`invocation_authority.rs` and the Slice 1382 helper-export deletion:
provider-result admission request shape is Rust-authored before JS can call
the typed admission API. Fixture/local-folder, native-local, and hosted
Rust-backed outputs remain admissible only through matching Rust backend,
response kind, custody, and transport evidence. This still does not claim
terminal provider migration: direct Rust daemon-core hosted/provider
transports, projection, Agentgres-backed reads, and command-transport
retirement remain required.

Slice 822 moved the provider-result backend invariant into the Rust
`model_mount` core. `ModelMountProviderResultAdmissionRequest::validate()` no
longer accepts `js_provider_driver_observation`; provider-result admission now
requires one of the Rust-owned provider result backends
(`rust_model_mount_fixture`, `rust_model_mount_native_local`, or
`rust_model_mount_native_local_stream`, plus the Rust-hosted provider backends
when wallet/vault/cTEE and hosted transport evidence are present) and binds the record with
`rust_model_mount_provider_result_backend_bound` evidence. The
`ioi-step-module-bridge` command path now proves fixture provider-result
admission through Rust and also proves the retired JS observation backend fails
closed with `UnsupportedProviderResultBackend`. This still does not claim
terminal provider migration: direct Rust daemon-core hosted/provider transports,
provider request shaping, projection, Agentgres-backed reads, and
command-transport retirement remain required.

Current public model invocation cut: public fixture/local-folder non-stream
invocation, native-local stream invocation, hosted non-stream invocation, and
hosted stream invocation now run through the Rust
`model_mount` route-selection receipt, provider-execution admission, provider
invocation/stream execution, provider-result admission, accepted-receipt
transition, receipt binding, StepModule projection, Agentgres state-root
binding, and Rust-authored invocation receipt persistence path. The migrated
public path is marked by `model_mount_invocation_positive_rust_path` and
`rust_daemon_core_model_invocation_receipt`, and no longer uses JS provider
drivers, JS invocation receipt creation, route-state persistence,
provider-native request-shaping hooks, or stream downgrade fallback. This still
does not claim terminal model invocation migration: live hosted/provider
transports, model loading and instance lifecycle truth, conversation-state and
stream-completion projection, durable projection/replay, deeper wallet/cTEE
invocation policy, and stable SDK/IDE invocation
APIs remain required.

Slice 823 retired the hosted/OpenAI-compatible JS provider invocation and
stream-invocation bodies. `OpenAICompatibleModelProviderDriver.invoke()` and
`.streamInvoke()` now fail closed with
`model_mount_provider_js_invocation_retired` before request-body shaping,
provider HTTP calls, token/result normalization, or provider-result assembly.
The vLLM, llama.cpp, and LM Studio wrappers now fail closed at their own
invocation boundaries before backend-process staging or public-CLI transport.
Catalog/health/lifecycle probes remain non-authoritative support surfaces, but
no hosted/OpenAI-compatible JS provider driver remains as an execution fallback.
This still does not claim terminal provider migration: direct Rust daemon-core
hosted/provider transports, provider request shaping, projection,
Agentgres-backed reads, and command-transport retirement remain required.

Slice 824 retired the remaining Ollama JS provider invocation and daemon-local
HTTP stream transport body. `OllamaModelProviderDriver.invoke()` and
`.streamInvoke()` now fail closed with
`model_mount_provider_js_invocation_retired` before Ollama `/api/chat` or
`/api/embeddings` request shaping, provider HTTP stream transport, token
estimation, output synthesis, or provider-result assembly. The shared
fail-closed boundary no longer preserves separate hosted and Ollama helper
bodies; `provider-invocation-retirement.mjs` is now absent after Slice 892. The
dead JS chat/Responses request and output translators plus generic
`fetchProviderStream()`/stream-timeout helper were removed rather than retained
as dormant compatibility scaffolding. Catalog/list/health and lifecycle probes
remain non-authoritative migration support only. This still does not claim
terminal provider migration: direct Rust daemon-core provider transports,
provider request shaping, projection, Agentgres-backed reads, lifecycle
ownership, and command-transport retirement remain required.

Slice 825 retired the default LM Studio public-discovery projection fallback.
Default seeding no longer runs the LM Studio public CLI to infer provider
status, no longer runs `lms ls` to mint artifact records, no longer creates the
legacy `lmstudio.detected` artifact fallback, and no longer prunes
LM Studio artifact/endpoint/instance projection maps from JS. Slice 897 then
deleted the retired `discoverLmStudioProvider()`, `discoverLmStudioArtifacts()`,
and `pruneLmStudioPublicProjectionRecords()` helpers, removed the mounted
`ModelMountingState` pass-through methods, removed the dead LM Studio list and
process parsers plus artifact projection helper from local-system probes, and
removed the unused `lmStudioPublicCliEnabled()` environment toggle. This still
does not claim terminal
provider inventory/projection migration: direct Rust daemon-core provider
inventory, lifecycle, Agentgres-backed projection reads, and command-transport
retirement remain required.

Slice 826 retired the hidden LM Studio runtime-survey public-CLI helper path.
Runtime survey capture already failed closed at the public facade; the helper
surface now also no longer runs `lms runtime ls` or `lms runtime survey`,
runtime engine listing no longer calls `state.lmStudioRuntimeEngines()`, the
aggregate model-mounting state no longer exposes LM Studio runtime helper
wrappers, and the runtime-specific LM Studio parser helpers plus public runtime
discovery env toggle are removed. In that slice, the remaining helper-level
exports still returned empty/not-checked Rust-boundary placeholders; later
runtime-survey facade-retirement work deleted those helpers entirely rather than
preserving them as compatibility scaffolding.
This still does not claim terminal runtime-survey migration: direct Rust
daemon-core runtime probing, Agentgres-admitted survey truth, and direct Rust
projection APIs remain required before the pure Rust substrate target is met.

Slice 827 retired the LM Studio provider driver's public-CLI command transport.
`LmStudioModelProviderDriver` no longer resolves `lmsPath`, no longer calls
`runPublicCommand`, no longer parses `lms ls`/`lms ps`, and no longer returns
public-CLI lifecycle/load evidence from JS. Its health, inventory, start/stop,
load, and unload methods now fail closed with
`model_mount_lm_studio_public_cli_retired` before any public-CLI transport or
command-result shaping. This still does not claim terminal LM Studio provider
migration: direct Rust daemon-core provider control, inventory, lifecycle,
Agentgres-backed projection reads, and command-transport retirement for the
remaining provider surfaces are still required.

Slice 828 retired the JS backend-process supervisor authority path.
`backend-lifecycle.mjs` helper module is deleted after its public backend
lifecycle and backend-process supervision entrypoints were reduced to
Rust-core-required edge refusals. Mounted public `ModelMountingState` backend
methods now own backend health/start/stop/log refusals,
`model_mount_backend_process_supervisor_retired`, and canonical Rust-boundary
metadata directly, without importing a backend lifecycle helper. Binary-backed
vLLM, llama.cpp, and Ollama lifecycle paths also fail before JS process staging
without importing that helper. The backend process entrypoints fail closed with
`model_mount_backend_process_supervisor_retired`. The native-local provider lifecycle path still calls the Rust `model_mount` planner, but now sends no JS process snapshot or local backend-log evidence. This still does not claim
terminal backend lifecycle migration: direct Rust daemon-core backend
lifecycle/control/projection APIs over Agentgres-backed state must replace the
remaining planner command transport, read adapters, and provider lifecycle
facades before the pure Rust substrate target is met.

Slice 829 retired the remaining JS provider HTTP transport/probe authority
path. `provider-transport.mjs` no longer performs `fetch()`, applies JS HTTP
timeouts, retries provider-open probes, resolves provider auth headers for
provider runtime requests, or tolerates live provider HTTP responses from JS;
Slice 892 later deleted the leftover wrapper module rather than preserving
`fetchProviderJson()` or `retryProviderOpen()` as fail-closed compatibility
surfaces. OpenAI-compatible, Ollama, vLLM, and llama.cpp driver
health/inventory/lifecycle methods now fail before
`/models`, `/api/tags`, `/api/ps`, or `/api/generate` request shaping, and the
Ollama catalog bridge no longer reaches through the JS provider driver for live
catalog truth. This still does not claim terminal provider migration: direct
Rust daemon-core provider transport, provider inventory/control projection,
wallet/cTEE vault material resolution, Agentgres-backed read APIs, and
replacement of command transport with direct Rust APIs remain required.

Slice 830 retired external live model-catalog HTTP search from the JS daemon
catalog-provider ports. The Hugging Face-compatible search helper module is
deleted, `model-mounting.mjs` no longer exposes `searchHuggingFaceCatalog()`,
and the Hugging Face-compatible plus custom HTTP catalog ports now return
`model_catalog_live_http_search_retired` with
`catalog_live_http_search_js_retired` evidence before catalog auth material,
`/api/models`, `/catalog/search`, timeout, or `fetchWithTimeout()` request
shaping can run in JS. Fixture catalog reads remain a local read adapter, while
local-manifest catalog search is retired in a later slice. This still does not
claim terminal catalog migration:
direct Rust daemon-core catalog search/provider transport, wallet/cTEE custody
resolution, Agentgres-backed catalog projection, and direct Rust APIs must
replace the remaining JS catalog status/search orchestration and local
materialization before the pure Rust substrate target is met.

Slice 831 retired the private JS OAuth credential custody helper. The mounted
model-mounting state no longer constructs `OAuthCredentialProvider`, and that
helper was later deleted after failing closed with
`model_mount_oauth_credential_provider_js_retired` before JS vault binding,
vault resolution, vault removal, authorization-code exchange, refresh, revoke,
or access-header resolution could run. `fetchOAuthToken()` now fails closed with
`model_mount_oauth_token_transport_retired` before
`fetchWithTimeout()`, form-body construction, timeout policy, or token endpoint
transport can run in JS, and OAuth boundary projections identify
`RustDaemonCore.catalogProviderOAuth` rather than the retired JS helper as the
exchange owner. This still does not claim terminal catalog-provider custody
migration: direct Rust daemon-core OAuth control, wallet/cTEE vault custody,
Agentgres-backed OAuth/session projection, and direct Rust APIs remain required
before OAuth-backed catalog/provider auth can execute again.

Slice 832 retired the remaining JS catalog-provider runtime-material and
non-OAuth auth-header vault-resolution helpers. That fail-closed boundary is now
superseded for catalog-provider control itself: the mounted
`catalogProviderRuntimeMaterial()` helper calls Rust daemon-core
`plan_model_mount_catalog_provider_control`, commits the Rust-authored
`model-catalog-provider-controls` record through Agentgres model_mount
record-state admission, and returns only cTEE-sealed runtime-material status
without resolving vault refs, parsing source material, or returning plaintext
material in JS. Catalog auth-header materialization remains absent until the same
Rust wallet/cTEE control family grows a dedicated auth-header response.

Slice 833 retired local-manifest catalog search materialization from the JS
catalog-provider port. `localManifestCatalogProviderPort()` no longer imports
filesystem/path APIs, calls `fs.existsSync()`, reads manifest JSON through
`localManifestCatalogEntries()`, or returns manifest entries from JS. The port
now exposes configuration metadata only and returns
`model_catalog_local_manifest_search_retired` with
`local_manifest_catalog_search_js_retired` evidence before local manifest search
can run. This still does not claim terminal catalog migration: direct Rust
daemon-core catalog search, Agentgres-backed projection, local catalog
materialization, and direct Rust APIs remain required before local-manifest
catalog search can execute again.

Slice 834 retired fixture catalog search materialization from the JS
catalog-provider port. `fixtureCatalogProviderPort()` no longer imports or
filters `fixtureModelCatalog()` entries and no longer returns deterministic
fixture catalog entries as JS search truth. The port still reports fixture
catalog health for product-safe status, but search now returns
`model_catalog_fixture_search_retired` with
`fixture_catalog_search_js_retired` evidence before fixture catalog
materialization can run in JS. Fixture metadata remains available only for
historical fixture tests; later slices retired the remaining non-search catalog
variant enrichment path as a JS authority surface.

Slice 835 retired public model catalog search orchestration from JS. The
mounted `catalogSearch()` facade stopped normalizing search filters, iterating
catalog provider ports, enriching catalog entries, aggregating provider results,
or writing `lastCatalogSearch`. That fail-closed JS coordinator has since been
superseded by the Rust `catalog_search` read projection over admitted provider
inventory records; the `model_catalog_search_js_orchestrator_retired` evidence
now marks the retired JS path, not the public return path.

Slice 836 retired public catalog-provider configuration list/get projection
from JS. `listCatalogProviderConfigs()` and `getCatalogProviderConfig()` now
fail closed at `model_mount.catalog_provider_configuration.list` and
`model_mount.catalog_provider_configuration.get` before JS can read local
configuration maps, resolve runtime material, iterate provider ports, call
`publicCatalogProviderConfig()`, or attach JS provider status. Broad
model-mount snapshot/projection transport also stops sending
`catalog_provider_configs`, and the Rust bridge no longer emits the
compatibility `catalogProviderConfigs` field. Catalog-provider configuration
readback is therefore blocked until direct Rust daemon-core catalog-provider
control/projection APIs own the request.

Slice 837 retired public catalog-status readback input composition from JS.
`catalogStatus()` and `catalogStatusProjectionInput()` initially failed closed with
`model_catalog_status_js_readback_retired` before JS can iterate catalog provider
ports, summarize storage, read `lastCatalogSearch`, or send `catalog_status_input`
to Rust. Broad model-mount snapshot/projection transport also stops sending
`catalog_status_input`; the remaining broad `catalog` envelope is a
non-authoritative empty/default Rust projection until direct Rust daemon-core
catalog status/projection APIs own the request.

Slice 867 moved public catalog-status readback refusal onto the Rust
read-projection boundary. The current macro cut supersedes that refusal:
public `catalogStatus()` now calls `plan_model_mount_read_projection` kind
`catalog_status` with empty request state plus runtime `state_dir` and returns
the Rust-authored catalog-status projection from admitted provider-inventory
replay. The JS edge no longer translates
`model_catalog_status_js_readback_retired`, the obsolete Rust refusal module is
deleted, and the direct Rust `catalog_status` arm ignores caller-supplied
`catalog_status_input` while returning provider status, storage status,
last-search summary, and result rows from admitted `model-provider-inventory`
records. This is still current-lane bridge work, not the long-term resting
architecture: direct Rust daemon-core catalog status/projection APIs must replace command transport
before the catalog surface
reaches terminal unification.

Slice 868 retired the remaining runtime-survey projection-input and LM Studio
runtime placeholder helpers from JS. At that point the runtime-daemon public
`runtimeSurvey()` facade still failed closed before hardware probes,
runtime-engine reads, LM Studio public-CLI execution, receipt creation, or
projection writes; later runtime-survey capture work moved that public edge to
Rust `plan_model_mount_runtime_survey` plus Rust Agentgres model_mount
receipt-state commit. The latest runtime-survey readback now uses Rust
`latest_runtime_survey` with empty request state plus runtime `state_dir`
receipt replay, so
`latestRuntimeSurveyProjectionInput()`,
`lmStudioRuntimeEngines()`, and `lmStudioRuntimeSurvey()` were deleted instead
of being preserved as non-authoritative compatibility shims. This is still not
terminal runtime-survey migration: richer runtime materialization, projection
persistence, and stable protocol APIs remain
required before runtime survey reaches the pure Rust substrate target.

Slice 838 retired the remaining non-search catalog variant enrichment path from
JS. Mounted catalog entry enrichment now fails closed with
`model_catalog_variant_enrichment_js_retired` before reading storage summaries,
artifact maps, max-byte policy, or local helper-generated backend/download/
recommendation fields. `catalogVariantForSource()` now fails closed at the same
Rust catalog-variant projection boundary before fixture lookup, legacy
camelCase variant aliases, catalog auth projection, or selection receipt-field
synthesis can become JS truth.

Slice 839 retired JS-authored provider public/vault metadata projection from
model_mount read-projection input. `providerList()` now returns sorted raw
provider records only, and the direct model_mount read-projection client no longer injects
`providerHasVaultRef` or `publicProvider` into provider, model-capability,
receipt-replay, latest-provider-health, snapshot, or projection requests. Public
provider envelope shaping and vault metadata redaction are therefore no longer
JS readback authority; direct Rust daemon-core projection APIs must own that
shape over Agentgres/wallet/cTEE admitted truth.

Slice 840 retired JS-authored OAuth session/state read projection from
model_mount readback. Public `listOAuthSessions()` and `listOAuthStates()`
initially failed closed with `model_mount_oauth_read_projection_js_retired`
before JS could call `publicOAuthSession()`, call `publicOAuthState()`, or
hash/redact custody material. Broad snapshot/projection transport no longer
sends `oauth_sessions` or `oauth_states`; any public OAuth session/state
envelope must be authored by direct Rust daemon-core wallet/cTEE projection over
admitted truth rather than by JS redaction helpers or migration payloads.

Slice 841 retired stale catalog-provider OAuth compatibility helper injection
from the mounted model_mount facade. `startCatalogProviderOAuth()`,
`completeCatalogProviderOAuth()`, `exchangeCatalogProviderOAuth()`,
`refreshCatalogProviderOAuth()`, and `revokeCatalogProviderOAuth()` now pass only
the minimal fail-closed boundary dependencies into `catalog-provider-oauth.mjs`:
provider configurability checks, callback `state` validation where required, and
runtime error construction. The mounted facade no longer imports or injects
`publicCatalogProviderConfig()`, `catalogProviderStatus()`,
`oauthBoundaryForSession()`, `publicOAuthSession()`, or `stableHash()` into
those OAuth facades, so a future edit cannot accidentally restore JS public
config/session projection, OAuth boundary redaction, or hash-derived custody
metadata through unused dependency hooks. Direct Rust daemon-core OAuth
control/projection APIs still need to replace the fail-closed facade before
terminal catalog-provider custody migration is complete.

Slice 842 retired stale public catalog-search orchestration helper injection
from the mounted model_mount facade. The mounted facade stopped injecting
`catalogProviderStatus()` or `normalizeLimit()` into the retired search
operation, and the current `catalogSearch()` public path now calls the Rust
`catalog_search` read projection instead. The public facade can therefore no
longer accidentally restore JS provider-status shaping, filter normalization,
provider iteration, entry enrichment, result aggregation, or `lastCatalogSearch`
writes through unused dependency hooks.

Slice 843 retired cached catalog-provider runtime-material readback from the JS
catalog-provider control surface. The current macro cut replaces that refusal
with a positive Rust path: `catalogProviderRuntimeMaterial()` now sends only the
provider id and canonical request facts to `plan_model_mount_catalog_provider_control`,
commits the Rust-authored control record through Agentgres, and returns the
Rust-authored cTEE custody envelope. It does not read
`catalogProviderRuntimeMaterials`, resolve vault refs, write vault metadata, or
let cached JS material become provider truth.

Slice 844 retired private catalog-provider configuration readback and
config-derived auth-header projection from JS. The current macro cut likewise
replaces the private-config refusal with Rust catalog-provider-control planning:
`catalogProviderConfig()` calls `plan_model_mount_catalog_provider_control` for
`model_mount.catalog_provider_configuration.read_private`, commits only the
Rust-authored record, and returns no plaintext material. Auth-header
materialization remains absent, and catalog-provider port health helpers still
cannot call JS config/runtime-material readers as admitted provider truth.

Slice 845 retired the remaining Ollama catalog-provider JS provider-map
readback from the catalog-provider port. `ollamaCatalogProviderPort()` no longer
reads `state.providers.get("provider.ollama")`, calls `catalogProviderStatus()`,
hashes JS `provider.baseUrl`, or reports configured provider truth from the JS
inventory map. At that slice, its port-local health/search metadata was only a
gated Rust-core-required migration placeholder. Slice 910 later deleted that
port helper surface entirely, so the long-term shape remains direct Rust
daemon-core model_mount/catalog-provider projection, not JS provider-map status
readback, JS port health metadata, or bridge-owned authority.

Slice 846 retired backend-registry provider-map readback from derived backend
records. Slice 1266 hard-retires backend registry derivation and seeding as a JS
truth path: `deriveBackendRegistry()`, `seedBackends()`, and
`backendRegistryRecords()` are absent from the mounted model_mount state and JS
default records. Backend projection truth now enters through Rust read-projection
kind `backends` over Agentgres-admitted lifecycle records; env/binary-gated JS
backend metadata can no longer become backend lifecycle/projection truth.

Slice 847 retired JS provider-status summaries from server-status projection
input. `serverStatusProjectionInput()` no longer reads `state.providers.values()`
or sends `provider_statuses` into `server_status_input`, so the runtime-daemon
cannot summarize provider readiness from local JS provider maps while Rust
authors the public server-status envelope. Direct Rust daemon-core
server-control/provider projection must own provider-state counts over admitted
Agentgres provider truth before terminal server-control projection is complete.

Slice 848 retired LM Studio provider-map seeding from default model-mounting
initialization. `seedModelMountingDefaults()` no longer calls
`state.discoverLmStudioProvider(checkedAt)` and no longer merges
`provider.lmstudio` into `state.providers`, even as absent/configured inert
metadata. Default seeding still records the retired LM Studio public projection
boundary, but provider inventory truth must now come from direct Rust
daemon-core provider inventory/projection APIs backed by admitted Agentgres
state rather than JS-discovered provider records.

Slice 849 retired JS backend-status summaries from server-status projection
input. `serverStatusProjectionInput()` no longer calls `state.listBackends()`
or sends `backend_statuses` into `server_status_input`, so the runtime-daemon
cannot summarize backend readiness from local JS backend records while Rust
authors the public server-status envelope. Direct Rust daemon-core
server-control/backend projection must own backend-state counts over admitted
Agentgres backend truth before terminal server-control projection is complete.

Slice 850 retired broad snapshot/projection backend registry and backend
process input from JS. The default model_mount read-projection input no longer
sends `backends: state.listBackends()` or
`backend_processes: state.listBackendProcesses()` for broad `snapshot` and
`projection` requests, so local JS backend registry/process maps cannot become
public projection truth through the broad Rust projection envelope. Direct Rust
daemon-core backend lifecycle/projection APIs over Agentgres-admitted backend
truth must own those arrays before terminal backend projection is complete.

Slice 851 retired broad snapshot/projection runtime-engine input from JS. The
default model_mount read-projection input no longer sends
`runtime_engines: state.listRuntimeEngines()`,
`runtime_engine_profiles: state.listRuntimeEngineProfiles()`, or
`runtime_preference: state.runtimePreference()` for broad `snapshot` and
`projection` requests. Dedicated runtime-engine read projections now send empty
JS state plus runtime `state_dir` and replay admitted `runtime-engine-controls`
records in Rust, so local JS runtime-engine maps/preferences can no longer
become public projection truth through either the broad Rust projection envelope
or the dedicated runtime-engine read surfaces.

Slice 852 retired broad snapshot/projection MCP and conversation input from JS.
The default model_mount read-projection input no longer sends
`mcp_servers: state.listMcpServers()` or
`conversation_states: state.listConversations()` for broad `snapshot` and
`projection` requests, so local JS MCP/conversation maps cannot become public
projection truth through the broad Rust projection envelope. Direct Rust
daemon-core projection APIs over Agentgres-admitted MCP and conversation truth
must own those arrays before terminal MCP/conversation projection is complete.

Slice 853 retired broad snapshot/projection authority and adapter-status input
from JS. The default model_mount read-projection input no longer sends
`grants: state.listTokens()`, `vault_refs: state.listVaultRefs()`,
`agentgres_store: state.store.adapterStatus()`,
`wallet: state.walletAuthority.adapterStatus()`, or
`vault: state.vaultStatus()` for broad `snapshot` and `projection` requests.
Rust now replays admitted `capability-tokens/*.json` and `vault-refs/*.json`
records into broad `projection` grants, broad `snapshot` tokens/vault refs, and
dedicated `authority_snapshot` grants/vault refs through the daemon-core
custody projection boundary, while `adapter_boundaries` still uses a narrow
Rust-planned input. Local JS wallet/vault/Agentgres adapter state can no longer
become public authority, custody, or adapter-boundary truth through the broad
Rust projection envelope.

Slice 854 retired broad snapshot/projection provider-health and runtime-survey
telemetry input from JS. The default model_mount read-projection input no
longer sends `provider_health: providerHealthList(...)` or
`runtime_survey_input: latestRuntimeSurveyProjectionInput(...)` for broad
`snapshot` and `projection` requests. Later dedicated-telemetry slices retired
the remaining `provider_health`, `latest_provider_health`, and
`latest_runtime_survey` JS input paths as well, so local JS provider-health
files and runtime-survey probe summaries cannot become public telemetry truth
through either the broad Rust projection envelope or the dedicated telemetry
readback path.

Slice 855 retired broad snapshot/projection model-topology input from JS. The
default model_mount read-projection input no longer sends `artifacts`,
`endpoints`, `instances`, `providers`, `routes`, `downloads`, or
`product_artifact_policy` for broad `snapshot` and `projection` requests.
Dedicated topology read projections still use narrow Rust-planned inputs, and
receipt replay still receives the topology slices it explicitly needs, but
local JS model topology maps can no longer become public projection truth
through the broad Rust projection envelope.

Slice 856 retired broad snapshot/projection server-status input from JS. The
default model_mount read-projection input no longer sends
`server_status_input: serverStatusProjectionInput(...)` for broad `snapshot`
and `projection` requests. Later Slice 1006 retired the remaining dedicated
`server_status_input` transport: the dedicated `server_status` read projection
now sends empty state and request-level `base_url`, while authority snapshot
uses empty request state plus runtime `state_dir` receipt replay. JS volatile
server-control state can no longer become
public server truth through either the broad Rust projection envelope or the
dedicated server-status readback.

Slice 857 retired dedicated authority and adapter-boundary JS read-projection
input. The `adapter_boundaries` read projection now sends an empty state object
and Rust authors wallet, vault, OAuth, and Agentgres boundary metadata directly
instead of echoing JS `adapterStatus()` objects. The `authority_snapshot` read
projection now sends empty request state plus runtime `state_dir` replay instead
of JS `server_status_input`, grants, vault refs, wallet status, vault status, or
caller-supplied receipt arrays. Rust replays admitted capability-token and
vault-control records into public grants/vault refs with token material and
plaintext vault material redacted. Direct Rust daemon-core wallet/vault/Agentgres
authority projection still needs to replace the remaining default authority
envelope before terminal authority projection is complete.

Slice 858 retired dedicated runtime-engine JS read-projection input. The
`runtime_engines`, `runtime_engine_profiles`, `runtime_preference`,
`runtime_preference_for_endpoint`, `runtime_default_load_options`, and
`runtime_engine_detail` read projections now send empty state objects from the
runtime-daemon facade and runtime `state_dir` for Agentgres replay. Rust now
requires `state_dir`, reads admitted `runtime-engine-controls/*.json` records,
filters out JS-authored controls, materializes engine/profile/preference/default
load projections from Rust-owned control records, and fails closed with
`model_mount_runtime_engine_not_found` only when the requested engine has no
admitted runtime-engine control truth. Command-transport replacement, stable
protocol APIs, and local runtime-engine materialization retirement still remain
before this surface reaches the pure Rust substrate target.

Slice 859 retired dedicated latest-runtime-survey JS primitive read-projection
input, and the current receipt-replay authority cut removed the later JS receipt
list transport as well. The `latest_runtime_survey` read projection now sends
empty request state plus runtime `state_dir` and no longer imports
`latestRuntimeSurveyProjectionInput()`, reads JS runtime-engine preferences,
passes JS hardware/probe fallback data, or transports caller-supplied receipt
arrays. Rust ignores `runtime_survey_input` and replays admitted
`receipts/*.json`: not-checked survey readback returns zero/null/default values,
and checked survey readback is derived only from admitted `runtime_survey`
receipt details. Direct Rust daemon-core runtime probing, Agentgres-admitted
survey capture, command-transport replacement, and local survey materialization
retirement still remain before this surface reaches the pure Rust substrate
target.

Slice 860 retired dedicated provider-health JS read-projection input, and the
provider-lifecycle replay cut moved provider-health list/latest truth from
receipt replay onto admitted lifecycle records. The `provider_health` read
projection now sends empty request state plus runtime `state_dir`; Rust replays
admitted `model-provider-lifecycle-controls/*.json` records into
`agentgres_provider_lifecycle_health` list entries carrying the lifecycle record,
null receipt field, projection replay envelope, and projection watermark. The
Rust bridge `provider_health` arm ignores caller-supplied provider-health records
and no longer returns the default empty list, so direct bridge callers cannot
promote local JS telemetry into projection truth or preserve a duplicate empty
truth path. The `latest_provider_health` read projection now sends empty request
state plus runtime `state_dir`, uses admitted provider-lifecycle records instead
of `provider_health` receipts, and no longer reads JS provider records, local
provider-health files, or caller-supplied receipt arrays. Rust derives
provider-health read envelopes from canonical provider-lifecycle records with
canonical `provider_id`; missing `state_dir` fails closed at
`model_mount_provider_lifecycle_replay_state_dir_required`, and missing latest
record truth fails closed with `model_mount_provider_health_not_found`. Actual
hosted/provider transports, deeper receipt/state-root binding beyond record-state
commit, command-transport replacement, and stable direct Rust daemon-core
provider-lifecycle APIs remain non-terminal.

Slice 861 retired dedicated model-topology list JS read-projection input. The
`artifacts`, `providers`, `endpoints`, `instances`, `routes`,
`model_capabilities`, and `downloads` read projections now send empty state
objects from the runtime-daemon facade; `instances`, `routes`, and
`model_capabilities` also send runtime `state_dir`. Rust replays admitted
instance, route, route-endpoint-resolution, provider-inventory, artifact, and
loaded-instance records for the migrated list/capability surfaces instead of
echoing caller-supplied topology arrays or returning the old capability-list
placeholder. This prevents local JS maps from becoming public topology or
capability-list truth through the dedicated list surfaces. Product artifact/catalog readbacks
and receipt replay remain separate migration seams: product-safe catalog
surfaces still receive artifact/policy input, and receipt replay still receives
the topology context it explicitly needs for replay until Rust-owned topology
lookup can replace that context.

Slice 862 retired dedicated product artifact/catalog JS read-projection input.
The `product_artifacts`, `runtime_model_catalog`, and `open_ai_model_list`
read projections now send empty state objects from the runtime-daemon facade,
and the Rust bridge direct arms return empty/default product/catalog lists
instead of filtering or translating caller-supplied artifact arrays. This
prevents local JS artifact maps and fixture policy from becoming public product
catalog or OpenAI-compatible model-list truth while direct Rust daemon-core
Agentgres-backed catalog/topology projection APIs are still pending. Broad
snapshot/projection catalog fields remain default/non-authoritative, and
receipt replay remains a separate topology-lookup migration seam.

Slice 863 retired broad snapshot/projection topology and product-catalog
materialization from caller-supplied bridge state. The Rust bridge now keeps
the public `snapshot` and `projection` envelope fields schema-stable but
returns empty/default topology, runtime-engine, MCP/conversation, and
product-catalog fields instead of honoring direct caller arrays. The retired
Rust product artifact, runtime catalog, OpenAI model-list, fixture filtering,
and ad hoc timestamp helper tree was deleted, and the focused JS fixture
planner mirrors the default envelope rather than reimplementing the old
derivation. Model-capability derivation now exists only as Rust Agentgres
replay, not as caller-supplied bridge-state derivation. Receipt replay remained
a separate topology-lookup seam.

Slice 864 retired receipt-replay topology input from the runtime-daemon facade
and Rust bridge. The `receipt_replay` read projection now sends only admitted
receipts plus `receipt_id`; Rust preserves the receipt and embedded
`model_route_decision` evidence but returns null route, endpoint, instance, and
provider enrichments until direct Rust daemon-core Agentgres topology lookup
owns those joins. The JS topology list imports and the Rust `projection_lookup`
compatibility helper were removed, so replay can no longer promote local JS
route/provider/endpoint maps into replay truth.

Slice 865 retired direct runtime-engine projection input from the Rust bridge.
The direct `runtime_engines`, `runtime_engine_profiles`, `runtime_preference`,
`runtime_preference_for_endpoint`, `runtime_default_load_options`, and
`runtime_engine_detail` read-projection arms now ignore caller-supplied
runtime-engine arrays, profiles, preferences, default-load options, and detail
objects. Rust requires runtime `state_dir`, replays admitted
`runtime-engine-controls` records for list/profile/preference/default-load/detail
truth, filters out JS-authored controls, and fails closed with
`model_mount_runtime_engine_not_found` only when the requested engine is absent
from admitted Agentgres runtime-engine control truth. This keeps
`ioi-step-module-bridge` as a temporary command transport and prevents direct
bridge callers from reintroducing
JS runtime-engine maps as projection truth.

Current OAuth read-projection cut supersedes the Slice 866 refusal. Public
`listOAuthSessions()` and `listOAuthStates()` now call
`plan_model_mount_read_projection` kinds `oauth_sessions` and `oauth_states`
with empty request state plus runtime `state_dir`; Rust
`model_mount/read_projection/oauth.rs` replays admitted
`model-catalog-provider-controls/*.json` records, filters out legacy JS OAuth
truth, returns redacted wallet/cTEE custody rows for OAuth sessions and states,
and the broad Rust `snapshot`/`projection` envelopes now call the same OAuth
replay instead of preserving empty compatibility slots. The JS edge no longer
translates the Rust refusal or reads local OAuth maps.
Command transport and richer wallet/cTEE OAuth execution/projection remain
non-terminal, but public OAuth readback is no longer fail-closed scaffolding.

Slice 867 moved public catalog-status readback refusal onto the Rust
read-projection boundary. The current macro cut replaces the empty/default
catalog-status envelope with Agentgres-backed replay: public `catalogStatus()`
now calls `plan_model_mount_read_projection` kind `catalog_status` with empty
request state plus runtime `state_dir`, and Rust replays admitted
`model-provider-inventory/*.json` records into catalog provider status, storage
status, last-search summary, and result rows while filtering JS-authored
inventory. Hosted/provider catalog transports, richer hosted catalog metadata,
command-transport replacement, and stable SDK/IDE catalog APIs still remain
before this surface reaches the pure Rust substrate target.

Slice 868 retired the runtime-survey projection-input and LM Studio runtime
placeholder helpers from JS. Latest runtime-survey readback now uses Rust
`latest_runtime_survey` empty-state plus `state_dir` receipt replay, so
`latestRuntimeSurveyProjectionInput()`, `lmStudioRuntimeEngines()`, and
`lmStudioRuntimeSurvey()` were deleted rather than preserved as
non-authoritative compatibility shims. Direct Rust daemon-core runtime probing,
Agentgres-admitted survey truth, projection persistence, command-transport
retirement, and stable protocol APIs remain required before runtime survey
reaches the pure Rust substrate target.

Slice 869 retired the orphaned JS `read-model.mjs` projection helper module and
its unit test after public model_mount list/catalog/health/projection readbacks
had moved to Rust read-projection kinds. The public daemon method names remain
protocol-facing facade methods, but JS no longer carries fallback list builders
for artifact, provider, endpoint, instance, route, model-capability, download,
provider-health, product-artifact, runtime-catalog, or OpenAI-compatible model
lists. This does not claim terminal model_mount migration: direct Rust
daemon-core Agentgres projection APIs, local map/projection materialization
retirement, command-transport replacement, and edge error-envelope translation
retirement still remain.

Slice 870 retired the one-function JS `runtime-survey.mjs` helper module after
runtime-survey capture had already failed closed and latest runtime-survey
readback had moved to Rust state-dir receipt replay. Later runtime-survey
capture work superseded that mounted edge refusal: public
`ModelMountingState.runtimeSurvey()` now calls Rust daemon-core
`plan_model_mount_runtime_survey`, commits only the Rust-authored
`runtime_survey` receipt through Rust Agentgres model_mount receipt-state
admission, and still avoids JS hardware probes, runtime-engine reads,
LM Studio public-CLI execution, and JS receipt creation. This does not claim
terminal runtime-survey migration: richer runtime materialization, projection
persistence, and stable protocol APIs remain
required.

Slice 871 retired the `catalog-provider-oauth.mjs` helper module after public
catalog-provider OAuth start/callback/exchange/refresh/revoke had already been
isolated from JS projection/custody helpers. The current macro cut supersedes
the old edge refusals: the mounted public `ModelMountingState` OAuth methods now
call Rust daemon-core `plan_model_mount_catalog_provider_control`, commit only
the Rust-authored `model-catalog-provider-controls` record through Agentgres
model_mount record-state admission, preserve callback `state` validation, and
never execute the JS OAuth credential provider, mutate OAuth/session maps, write
vault refs, or return plaintext material. OAuth state/session projection and
command-transport retirement remain non-terminal.

The storage helper-retirement cut has been superseded by a typed Rust
storage-control API. Public download-cancel, artifact-delete, and
storage-cleanup mutations now call
`daemonCoreModelMountApi.planModelMountStorageControl`, backed by Rust
`RuntimeKernel::plan_model_mount_storage_control`, receive Rust-authored
`model-downloads` or `model-storage-controls` records, and require Agentgres
model_mount record-state commit before public truth returns. The mounted public `ModelMountingState`
storage methods still own canonical storage request alias rejection, while
`storageSummary()`, `listDownloads()`, and `downloadStatus()` now call Rust
model_mount read-projection kinds over runtime `state_dir`, replay admitted
storage-control records, and filter out JS-authored storage/download truth. JS
no longer preserves the storage-control command-envelope builder/operation,
bridge response wrapper, lifecycle receipts, direct download/artifact map
mutation, download-status map readback, filesystem scanning/mutation, or
no-commit planner success. This remains non-terminal: richer filesystem custody,
richer catalog/download materialization, and stable protocol APIs remain
required.

The capability-token cut now supersedes the earlier fail-closed helper
retirement. Public capability-token create/list/authorize/revoke call Rust
daemon-core `plan_model_mount_capability_token_control`, receive Rust-authored
`capability-tokens` records with wallet.network authority evidence, commit only
those records through Rust Agentgres model_mount record-state admission, and
return committed Rust response envelopes. Rust replays admitted
`capability-tokens/*.json` records for list/authorize/revoke; committed records
persist token hashes and authority facts without plaintext token material, while
one-time token material is returned outside the persisted record. The old
`capability-token-operations.mjs` helper, `publicToken()` formatter, JS token
maps, JS walletAuthority grant helpers, JS permission-token receipts, and direct
token-map projection remain retired. Broad Rust `projection`, `snapshot`, and
`authority_snapshot` now replay the same admitted capability-token control
records for public grants/tokens instead of returning caller-supplied JS token
arrays. Bearer-shape preflight may stay at the JS
protocol edge, but wallet authority, scope authorization, revocation, replay,
and projection truth now belong to Rust daemon core over Agentgres records.

The public vault route family now has a positive Rust daemon-core owner. Public
vault bind/list/metadata/status/health/remove call
`plan_model_mount_vault_control`, receive Rust-authored `vault-refs` records
with wallet.network authority and cTEE custody evidence, commit only those
records through Rust Agentgres model_mount record-state admission, and return
committed Rust response envelopes. Rust replays admitted
`vault-refs/*.json` bind/remove records for list/metadata/status/health, while
broad Rust `projection`, `snapshot`, and `authority_snapshot` now replay the
same admitted vault-control records into redacted public vault refs instead of
returning caller-supplied JS vault arrays. Committed records persist
vault_ref_hash, material_hash, custody facts, and authority facts without
plaintext material. The old `vault-operations.mjs`
helper, `publicVaultRefs()` formatter, JS vault metadata writer, direct public
vault-port mutation, JS vault receipts, and JS metadata/status readbacks remain
retired. The mounted public `ModelMountingState` vault methods now only own
canonical request alias rejection, required `vault_ref`/`material` preflight,
material hashing, Rust planning, Rust record commit, and committed-response
forwarding. Remaining non-terminal work is deeper cTEE material storage,
live outbound provider-auth injection, and stable
protocol APIs.

Slice 875 retired the fail-closed `tokenizer-operations.mjs` helper module after
public tokenize/count/context-fit utilities had already been reduced to
Rust-core-required model tokenizer edge refusals. The mounted public
`ModelMountingState` tokenizer/context-fit methods now own canonical tokenizer
request alias rejection, operation-specific `model_mount.tokenizer`
Rust-core-required errors, and context-window fallback reads directly, without
importing a helper module or dependency-injecting JS tokenization/truncation
helpers. This does not claim terminal tokenizer migration: direct Rust
daemon-core tokenizer/context-fit admission and projection, receipt/state-root
binding, Agentgres truth, replay, and stable
protocol APIs remain required.

Slice 876 retired the fail-closed `artifact-endpoint-operations.mjs` helper
module after public import/mount/unmount mutations had already been reduced to
Rust-core-required artifact/endpoint edge refusals. The mounted public
`ModelMountingState` artifact/endpoint methods now own canonical import,
endpoint mount, and endpoint unmount request alias rejection plus
operation-specific `model_mount.artifact_endpoint` Rust-core-required errors
directly, without importing a helper module or dependency-injecting JS artifact
inspection, materialization, metadata parsing, provider lookup, or endpoint
mutation helpers. This does not claim terminal artifact/endpoint migration:
direct Rust daemon-core artifact and endpoint admission, filesystem custody,
receipt/state-root binding, Agentgres truth, replay, command-transport
retirement, and stable protocol APIs remain required.

The catalog/download helper-retirement cut has also been superseded by the
typed Rust storage-control API. Public catalog-import URL and direct
model-download mutations now call
`daemonCoreModelMountApi.planModelMountStorageControl`, backed by Rust
`RuntimeKernel::plan_model_mount_storage_control`, receive Rust-authored
`model-catalog-imports` or `model-downloads` records, and require Agentgres
model_mount record-state commit before public truth returns. The mounted public
`ModelMountingState` catalog/download methods still own canonical catalog import
URL, download identity, download control, and download metadata request alias
rejection, but do not preserve JS transfer, fixture/live materialization,
filesystem, artifact/download record-state, or receipt helpers as fallback
truth. This remains non-terminal: richer catalog/download replay/projection,
filesystem custody, receipt/state-root binding beyond record-state commit,
and stable protocol APIs remain required.

Slice 878 retired the fail-closed
`catalog-provider-configuration-operations.mjs` helper module after public
catalog-provider config list/get/write and private runtime-material/config
readback had already been reduced to Rust-core-required wallet/cTEE custody
edge refusals. The mounted public `ModelMountingState` catalog-provider control
methods now own provider configurability preflight, configurable-provider count
reporting, request-field counting, local runtime-material status summaries, and
`model_mount.catalog_provider_configuration.*` /
`model_mount.catalog_provider_runtime_material.resolve` Rust-core-required
errors directly, without importing a helper module or dependency-injecting JS
projection, vault, runtime-material, receipt, or record-state helpers. This
does not claim terminal catalog-provider control migration: direct Rust
daemon-core catalog-provider control/search/status/custody APIs,
wallet.network/cTEE vault binding, Agentgres-admitted receipts and record-state
truth, projection persistence, and stable protocol APIs remain required. The
former `ioi-step-module-bridge` command path was migration scaffolding for
proving a stable daemon-to-kernel protocol surface, not a permanent bridge
binary, and is now deleted rather than preserved as a terminal substrate.

Slice 879 retired the fail-closed `receipt-operations.mjs` helper module after
direct model lifecycle receipt authoring and generic model_mount JS receipt
creation had already been reduced to Rust-core-required receipt-authoring edge
refusals. The mounted public `ModelMountingState` receipt methods now own
receipt list/get store adapters, lifecycle subject alias rejection,
`model_mount.lifecycle_receipt` Rust-core-required errors, generic JS
receipt-creation retirement, and Rust-authored receipt persistence validation
directly, without importing a helper module or preserving a standalone JS
receipt-authoring surface. This does not claim terminal receipt migration:
direct Rust daemon-core receipt authoring, binding, Agentgres admission,
state-root/expected-head checks, projection persistence, command-transport
retirement, and stable protocol APIs remain required.

Slice 880 retired the fail-closed `conversation-operations.mjs` helper module
after model conversation-state writes and stream-completion finalization had
already been reduced to Rust-core-required conversation admission/projection edge
refusals. The mounted public `ModelMountingState` conversation methods now own
response-id collision checks, previous-response read adapters,
`model_mount.conversation` Rust-core-required errors, stream-completion refusal
details, and conversation-state write refusal details directly, without
importing a helper module or preserving a standalone JS conversation mutation
surface. Slice 948 then retired the remaining `listConversations` JS map
readback, and the current positive cut routes public `listConversations()`
through Rust read-projection kind `model_conversation_states` with runtime
`state_dir`. Rust replays persisted `model-conversations/*.json` Agentgres
records, filters the public list to Rust-authored conversation records with
conversation hashes, conversation/stream evidence, and Agentgres
conversation-truth evidence, and returns projection truth without public-list
JS record candidates. This does not claim terminal conversation migration:
deeper wallet/cTEE authority, live hosted stream completion/finalization
materialization, and stable protocol APIs remain required.

Slice 881 retired the fail-closed `provider-operations.mjs` helper module after
provider upsert, health, inventory, and start/stop control had already been
reduced to Rust-core-required provider control/health/inventory edge refusals.
The mounted public `ModelMountingState` provider methods now own provider
upsert alias rejection, vault-ref normalization, `model_mount.provider_control`,
`model_mount.provider_health`, and `model_mount.provider_inventory`
Rust-core-required errors directly, without importing a provider operations
helper or preserving a standalone JS provider mutation/inventory surface. This
does not claim terminal provider migration: direct Rust daemon-core provider
control, wallet/cTEE vault authority, provider health/inventory projection,
Agentgres record-state truth, receipt/state-root binding, command-transport
retirement, replay, and stable protocol APIs remain required.

Slice 882 retired the fail-closed `mcp-workflow-operations.mjs` helper module
after MCP import, ephemeral MCP registration, MCP tool invocation, and
workflow-node execution had already been reduced to Rust-core-required
MCP/workflow control edge refusals. The mounted public `ModelMountingState` MCP
methods now own MCP import aliases, ephemeral integration aliases, MCP server
config aliases, MCP tool invocation aliases, workflow-node request aliases,
MCP server normalization/list sorting, and `model_mount.mcp_workflow`
Rust-core-required errors directly, without importing an MCP workflow helper or
preserving a standalone JS MCP/workflow mutation surface. This does not claim
terminal MCP/workflow migration: direct Rust daemon-core MCP/workflow APIs,
wallet authority, StepModuleRouter dispatch, receipt binding, Agentgres
admission, projection, replay, and stable
protocol APIs remain required.

Slice 883 retired the fail-closed `model-loading-operations.mjs` helper module
and the later public load/unload cut replaced the mounted edge refusal with a
positive Rust client. The mounted public `ModelMountingState` model-loading
methods now reject canonical load request aliases at the edge, ask Rust
`plan_model_mount_provider_lifecycle` for the provider lifecycle hash, ask Rust
`plan_model_mount_instance_lifecycle` for the model-instance transition record,
commit that Rust-authored record through Rust Agentgres
`commit_runtime_model_mount_record_state`, and only then return the committed
Rust record. JS still does not call provider drivers, create lifecycle
receipts, write `model-instances` maps, refresh `state.instances`, or run a
standalone model-loading helper. The later maintenance cut moved loaded-instance idle eviction,
duplicate coalescing, and explicit supersede onto the same Rust
`plan_model_mount_instance_lifecycle` plus Rust Agentgres model-instance
record-state commit path, including Rust-authored `reason` and `superseded_by`
metadata for maintenance transitions, while leaving the JS `state.instances`
cache unchanged after commit. This does not claim terminal instance
lifecycle migration: direct Rust projection/replay, deeper receipt/state-root
binding, and stable protocol APIs remain
required.
Slice 930 retired the remaining JS estimate-only model-load projection path:
`ModelMountingState.loadEstimate()` and `estimateNativeLocalResources()` are
absent. The canonical `load_options.estimate_only` now calls Rust
instance-lifecycle estimate planning at `model_mount.instance.estimate`,
receives a Rust-authored `load_estimate` record with provider lifecycle
execution, JS sizing, and JS driver execution all false, commits a
Rust-authored model-instance estimate record through Rust Agentgres, and
returns only that committed estimate truth without instance-map mutation.
Slice 931 retired the JS synthetic embedding-vector fallback. OpenAI-compatible
and native embedding responses now require a Rust/provider-authored
`providerResponseKind: "embeddings"` result with provider response vectors;
otherwise `openAiEmbedding()` fails closed at
`model_mount.provider_result.embeddings` before JS can derive deterministic
vectors from request text.
Slice 932 retired the public JS model-load estimate route. The native
model-mounting route handler no longer routes
`/api/v1/models/estimate-load`; `/api/v1/models/estimate-load` is no longer routed,
so callers cannot preserve the retired estimate-only facade through a
route-shaped compatibility wrapper after `load_options.estimate_only` moved to
the Rust-owned `model_mount.instance.estimate` planning and Agentgres commit
boundary.
Slice 933 retired the load-option `estimateOnly` compatibility alias. The
load-option normalizer now honors only canonical `estimate_only`, and
`canonicalLoadOptionsInput()` strips `estimateOnly` before provider/runtime
normalization, so the retired public estimate path cannot be steered through a
camelCase request alias while canonical `estimate_only` now enters the
Rust-owned `model_mount.instance.estimate` path.
Slice 934 retired the load-option `gpuOffload` compatibility alias. The
load-option normalizer now honors only canonical `gpu_offload` or `gpu`, and
`canonicalLoadOptionsInput()` strips `gpuOffload` before provider/runtime
normalization, so GPU placement cannot be steered through a camelCase
compatibility selector while backend process planning remains Rust-authored.
Slice 935 retired the load-option `contextLength` compatibility alias. The
load-option normalizer now honors only canonical `context_length`, and
`canonicalLoadOptionsInput()` strips `contextLength` before provider/runtime
normalization, so context-window steering cannot bypass the Rust-authored
backend process plan through a camelCase compatibility selector.
Slice 936 retired the load-option `ttlSeconds` and `idleTtlSeconds` compatibility aliases. The
load-option normalizer now honors only canonical `ttl_seconds`, `ttl`, or `idle_ttl_seconds`,
and explicit TTL detection no longer treats camelCase TTL request fields as
authoritative, so lifecycle TTL steering cannot survive as a JS compatibility
selector before Rust-core load admission owns the direct path.
Slice 937 retired the remaining load-option camelCase compatibility selectors. The
load-option normalizer now honors only canonical `instance_identifier`, `model_path`, `tensor_parallel_size`, `gpu_memory_utilization`, and `max_model_len`,
so instance identity, model-path, tensor-parallel, GPU-memory, and model-length
steering cannot survive as JS compatibility selectors before Rust-core load
admission owns the direct path.
Slice 938 retired load-policy camelCase compatibility selectors. The
load-policy normalizer now honors only canonical `ttl_seconds`, `ttl`, `idle_ttl_seconds`, `auto_evict`, and `memory_pressure_evict`,
so lifecycle TTL, idle eviction, and memory-pressure eviction policy steering
cannot survive as camelCase JS compatibility selectors before Rust-core load
admission owns the direct path.
Slice 939 retired the internal fixture-model environment compatibility selector. The
model-mounting environment adapter now honors only `IOI_EXPOSE_INTERNAL_FIXTURE_MODELS`;
`IOI_ENABLE_INTERNAL_FIXTURE_MODELS` no longer enables internal fixture seeding
or approval/runtime test setup, so fixture exposure cannot survive as a hidden
legacy env selector while Rust-owned provider and projection paths continue to
replace daemon-side JS scaffolding.
Slice 940 retired the visual GUI local fixture environment selectors. The
visual GUI local capture/executor helpers no longer read
`IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE` or
`IOI_RUNTIME_ENABLE_VISUAL_EXECUTOR_FIXTURE`; fixture capture and fixture local
execution are selected only by canonical request fields and fixture payloads,
so visual GUI test providers cannot be toggled by hidden daemon env selectors
while computer-use execution continues moving toward Rust daemon-core custody.
Slice 941 retired JS storage-summary filesystem scanning, and the later storage
read-projection cut replaced the fail-closed edge with Rust replay. Public
`ModelMountingState.storageSummary()` now calls the Rust
`storage_summary` read-projection kind over runtime `state_dir` instead of
recursively listing model files, computing quota totals, or classifying orphans
from JS maps and local filesystem state. `catalog-helpers.mjs` no longer exports
`listModelFiles()`, `modelFileScore()`, or `parseModelQuantization()`, and
`downloadStatus()` now calls the Rust `download_status` projection instead of
reading the JS download map.
Slice 942 retired JS native fixture artifact file materialization. Internal
fixture seeding may still create an explicit fixture artifact record when
`IOI_EXPOSE_INTERNAL_FIXTURE_MODELS` is set, but
`ensureNativeLocalFixtureArtifact()` no longer imports filesystem helpers,
creates `native-fixture/autopilot-native-fixture.Q4_K_M.gguf`, hashes that
file, parses local model metadata, or emits `artifactPath` as storage truth.
The native-local fixture record is now marked as a Rust-backed deterministic
fixture (`source: rust_model_mount_native_local_fixture`) and depends on the
Rust `model_mount` native-local backend for execution semantics.
Slice 943 retired the public backend list JS projection. `/api/v1/backends`
and `/api/v1/models/backends` remain mounted daemon protocol routes, but
`ModelMountingState.listBackends()` no longer returns `backendRegistry()`
records derived from JS env, discovery, provider maps, or process maps. A later
backend-lifecycle projection cut moved that public list to Rust read-projection
kind `backends` with empty JS request state plus runtime `state_dir`; Rust now
replays admitted `model-backend-lifecycle-controls/*.json`, filters
JS-authored lifecycle controls, and materializes backend projection truth from
Rust-owned lifecycle records. The remaining backend registry state is migration
plumbing for backend process planning/default records only; terminal
conformance still requires direct Rust process supervision, backend process
state materialization, and stable backend
protocol APIs.
Slice 944 removed backend-registry snapshots from native fixture materialization.
The Rust-backed native fixture artifact and endpoint records no longer carry
`backendRegistry` arrays from `state.backendRegistry()`, and fixture seeding no
longer calls that JS registry read while creating the artifact/endpoint records.
The records remain deterministic migration fixtures only; backend inventory,
process state, and lifecycle projection must come from direct Rust daemon-core
model_mount projection over Agentgres-admitted truth.
Model-mounting MCP workflow import, ephemeral registration, tool invocation,
workflow-node execution, and server list readback now use the typed
`daemonCoreModelMountApi.planModelMountMcpWorkflow` positive API backed by Rust
`RuntimeKernel::plan_model_mount_mcp_workflow`; the old command operation,
dispatch arm, bridge response wrapper, backend tag, and command-envelope builder
are retired. Rust authors the `mcp-servers` or `mcp-workflow-controls` records,
evidence refs, receipt refs, workflow hashes, authority hashes, and custody
facts before JS can commit record-state truth through Rust
Agentgres admission. MCP tool invocation and workflow-node execution now return
Rust-admitted execution/StepModule dispatch contracts, bind containment into the
authority hash, expose content receipt refs, omit retired JS/command/binary-
bridge/compatibility fallback proof fields, and reject stale `rust_required` or
fallback-proof public responses at the JS model-mount core boundary.
Public
`ModelMountingState.listMcpServers()` now calls Rust read-projection kind
`mcp_servers` with runtime `state_dir`; Rust replays persisted
`mcp-servers/*.json`, filters to Rust-authored MCP workflow records, and returns
redacted server projections. `publicMcpServer()`, direct JS MCP receipt
synthesis, JS MCP server map mutation/readback, JS route tests, JS
receipt-gate dispatch, JS model invocation, and the old projection-required
refusal shim stay retired. Runtime MCP catalog status/list/search may still
project workspace/agent MCP records through Rust planner commands; actual
model-mounting MCP transport backend materialization remains pending until Rust
daemon-core transport custody, wallet/containment authority, result content
receipts, replay/projection storage, and stable protocol APIs exist.
Slice 946's public capability-token projection retirement is now advanced by the
positive Rust capability-token control path. Public `ModelMountingState`
create/list/authorize/revoke calls Rust daemon-core
`plan_model_mount_capability_token_control`; list and authorization replay
admitted `capability-tokens/*.json` records instead of JS token maps, and
committed records preserve only hashes plus wallet authority facts. Broad
model-mount read projections now use the same Rust custody replay for public
grants/tokens. `/api/v1/tokens`
remains a mounted protocol edge over Rust-owned capability-token records, not a
JS projection/readback owner.
Slice 947's public vault projection retirement is now advanced by the positive
Rust vault-control path. Public `ModelMountingState.listVaultRefs()`,
`vaultRefMetadata()`, and `vaultStatus()` call
`plan_model_mount_vault_control`; Rust replays admitted `vault-refs/*.json`
bind/remove records and returns Rust-authored projection envelopes without
plaintext material. Broad model-mount read projections now use the same Rust
custody replay for redacted vault refs. `/api/v1/vault/refs`, `/api/v1/vault/refs/meta`, and
`/api/v1/vault/status` are mounted protocol edges over Rust-owned vault records,
not JS metadata/status projection owners.
Slice 948 retired model-mount conversation-state JS list readback, and the
current positive model conversation list cut replaces the fail-closed public
edge with Rust read-projection kind `model_conversation_states`.
`ModelMountingState.listConversations()` no longer returns
`this.conversations` sorted by `created_at` as JS-authored projection truth;
Rust emits only conversation records with the `model_mount.conversation`
boundary, conversation hash, Rust conversation-state or stream-completion
evidence, and Agentgres conversation-truth evidence by replaying persisted
`model-conversations/*.json` Agentgres records from the runtime `state_dir`.
deeper wallet/cTEE authority, hosted stream
parity, and stable protocol APIs remain required before terminal conformance.
Slice 949 now has a positive Rust read projection boundary instead of only a
retired JS readback facade. Public `RuntimeSubagentControl.listSubagents()`,
`getSubagent()`, and `getSubagentResult()` call Rust daemon-core
`project_runtime_subagent_projection`; the Rust core owns parent-thread
filtering, role filtering, subagent id selection, result envelope shaping,
projection-kind validation, receipt refs, and evidence refs before any public
route returns. Missing or mismatched Rust projection fails closed before JS
`subagents`/`runs` map readback. Direct Rust daemon-core subagent
admission/storage/replay over Agentgres-admitted lifecycle truth remains
required before terminal conformance.
Slice 949 also now has a positive Rust wait-control boundary for
`RuntimeSubagentControl.waitSubagent()`. The surface requires
`plan_runtime_subagent_control`, Rust runtime-event Agentgres admission, Rust
subagent record state-update planning, and Agentgres-backed `writeSubagent`
before returning wait output. Public `assignSubagent()` and `cancelSubagent()`
now use the same Rust control planner, Rust runtime-event admission, Rust
subagent record state-update planning, and Agentgres-backed persistence; cancel
also composes with the Rust run-cancel state-update path. Public
`sendSubagentInput()` and `resumeSubagent()` now use the same Rust control/state
path and create child-agent runs through the Rust-owned agent/run lifecycle
surface. `spawnSubagent()` now uses the same Rust control/state path, composes
with Rust-owned child-agent and child-run creation, admits the Rust-authored
spawn event, and persists only the Rust-planned subagent projection. The
propagation path now uses Rust read projection for candidate selection, Rust
`subagent.cancel.propagate` control planning, Rust run-cancel state planning,
Rust subagent record state-update planning, and Agentgres-backed
`writeSubagent`; direct control-event append now uses Rust
`plan_runtime_subagent_control` and Rust runtime-event Agentgres admission
without JS event authorship or subagent record mutation.
Slice 950 retired runtime task/job public JS readback. Public
`RuntimeTaskJobControl.listTasks()`, `getTask()`, `listJobs()`, and `getJob()`
now fail closed at `task.list`, `task.get`, `job.list`, and `job.get` with
`runtime_task_job_control_rust_core_required`, so JS no longer derives task/job
projection truth from `store.listRuns()`. Direct Rust daemon-core task/job
projection over Agentgres-admitted run/task/job truth remains required before
terminal conformance.
Slice 959 retired the daemon-store task/job route pass-through wrappers. The
public task/job create/list/get routes now call the fail-closed
`RuntimeTaskJobControl` surface directly, and the public task/job cancel routes
call the same surface instead of daemon-store compatibility wrappers. JS no
longer preserves `createTask()`, `listTasks()`, `getTask()`, `cancelTask()`,
`listJobs()`, `getJob()`, or `cancelJob()` as daemon-store wrappers. This does
not claim terminal task/job admission/projection: direct Rust daemon-core route
admission, wallet lifecycle authority, StepModuleRouter dispatch, Agentgres
expected-head/state-root binding, receipt/event materialization, replay,
projection, and stable SDK/IDE/CLI protocol APIs
remain required before terminal conformance.
Slice 960 retired the daemon-store admission route pass-through wrappers for
governed improvement proposals, external capability exits, worker/service
package invocations, cTEE private workspace actions, and L1 settlement
attempts. The public thread admission routes now call the mounted
Rust-backed/fail-closed admission surfaces directly, so JS no longer preserves
`admitGovernedImprovementProposal()`,
`authorizeExternalCapabilityExit()`,
`admitWorkerServicePackageInvocation()`,
`executeCteePrivateWorkspaceAction()`, or `admitL1SettlementAttempt()` as
daemon-store compatibility wrappers. This does not claim terminal admission
migration: direct Rust daemon-core route admission, wallet.network authority,
cTEE custody enforcement, StepModuleRouter dispatch, Agentgres
expected-head/state-root binding, receipt/event materialization, replay,
projection, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 961 retired the daemon-store route pass-through wrappers for workflow
edit apply, diagnostics repair decision execution, workspace snapshot list, and
workspace restore preview/apply. Those public thread routes now call the
mounted workflow-edit, diagnostics-repair, and workspace-snapshot surfaces
directly, so JS no longer preserves `applyWorkflowEditProposal()`,
`executeDiagnosticsRepairDecision()`, `listWorkspaceSnapshots()`,
`previewWorkspaceSnapshotRestore()`, or `applyWorkspaceSnapshotRestore()` as
daemon-store compatibility wrappers. This does not claim terminal workflow,
diagnostics, or workspace-snapshot migration: direct Rust daemon-core route
admission, wallet/cTEE authority where applicable, Agentgres
expected-head/state-root binding, receipt/artifact materialization, replay,
projection, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 962 retired the daemon-store approval route pass-through wrappers. The
public approval request, decision, approve/reject shortcut, and revoke routes
now call the mounted fail-closed approval surface directly, so JS no longer
preserves `requestThreadApproval()`, `decideThreadApproval()`, or
`revokeThreadApproval()` as daemon-store compatibility wrappers. This does not
claim terminal approval authority migration: direct Rust daemon-core route
admission, wallet.network grant/lease issuance, Agentgres expected-head and
state-root binding, receipt/event materialization, replay, projection,
stable SDK/IDE/CLI protocol APIs remain
required before terminal pure Rust substrate conformance.
Slice 963 retired the daemon-store context-policy route pass-through wrappers.
The public workflow-only context-budget, thread context-budget, thread
compaction-policy, thread compact, and run context-budget routes now call the
mounted context-policy surface directly, so JS no longer preserves
`evaluateContextBudget()`, `evaluateCompactionPolicy()`, or `compactThread()`
as daemon-store compatibility wrappers. Public `compactThread()` has since
moved to Rust-planned event and state-update ownership with Rust Agentgres
runtime-event admission and Agentgres-backed run/agent commits. Public
thread/run context-budget evaluation now requires Rust
`evaluateContextBudgetPolicy`, validates the Rust-authored policy-event
identity, and admits the Rust-planned context-budget runtime event before
returning route truth. Public thread compaction-policy evaluation now requires
Rust `evaluateCompactionPolicy`, admits the Rust-authored compaction-policy
runtime event, and composes Rust-approved compaction execution through the
Rust-owned `compactThread()` path. This does not claim terminal context-policy
migration: direct Rust daemon-core route admission, durable Agentgres
expected-head/state-root binding across context-policy routes, richer policy
receipt/event materialization, replay, projection,
and stable SDK/IDE/CLI protocol APIs remain required before terminal pure Rust
substrate conformance.
Slice 964 retired the daemon-store MCP route pass-through wrappers. Public MCP
catalog, validation, import/add/remove/enable/disable, invoke, and serve
routes plus thread-scoped MCP import/add/remove/enable/disable, search/fetch,
invoke, serve, status, and validation routes now call the mounted MCP catalog,
control, and serve surfaces directly. JS no longer preserves the route-facing
MCP store wrappers as compatibility authority. This does not claim terminal MCP
migration: direct Rust daemon-core MCP admission/projection, wallet.network
external-exit authority, Agentgres expected-head/state-root binding, MCP
receipt/event materialization, replay, and stable
SDK/IDE/CLI protocol APIs remain required before terminal pure Rust substrate
conformance.
Slice 965 retired the remaining route-facing daemon-store pass-through
wrappers for workflow-edit proposal admission and run-level coding-tool budget
recovery. The thread workflow-edit proposal route now calls the mounted
workflow-edit surface directly, and the run coding-tool budget recovery route
now calls the mounted fail-closed budget-recovery surface directly. JS no
longer preserves `proposeWorkflowEdit()` or
`codingToolBudgetRecoveryForRun()` as daemon-store route compatibility
wrappers. This does not claim terminal workflow-edit or coding-tool budget
recovery migration: direct Rust daemon-core admission/projection,
wallet.network approval authority where applicable, Agentgres expected-head and
state-root binding, receipt/event materialization, replay, command-transport
retirement, and stable SDK/IDE/CLI protocol APIs remain required before
terminal pure Rust substrate conformance.
Slice 966 moved the workflow-edit proposal/apply Rust-core-required admission
refusal into the Rust daemon-core policy bridge. `WorkflowEditAdmissionRequiredCore`
now emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes `plan_workflow_edit_admission_required`, and
the runtime daemon mounts that runner into the workflow-edit surface. JS still
translates the Rust-authored refusal at the HTTP edge, but no longer has to be
the canonical author for the workflow-edit admission-required envelope when the
daemon-core command is configured. This does not claim terminal workflow-edit
migration: direct Rust daemon-core proposal/apply admission, wallet.network
approval authority, Agentgres expected-head/state-root binding,
receipt/event materialization, replay, projection, command-transport
retirement, and stable SDK/IDE/CLI protocol APIs remain required before
terminal pure Rust substrate conformance.
The later workflow-edit control cut supersedes the route-facing refusal path for
proposal/apply event materialization: public workflow-edit proposal and apply
now require Rust daemon-core `plan_runtime_workflow_edit_control` and Rust
runtime-event Agentgres admission before returning accepted control truth.
The earlier Slice 967 refusal bridge for coding-tool budget recovery has been
superseded by the positive Rust control boundary. `CodingToolBudgetRecoveryControlCore`
now authors `request_approval` and `approve_override` run projections, the
daemon-core command surface exposes `plan_coding_tool_budget_recovery_control`,
and the runtime daemon commits only the Rust-planned run through Agentgres-backed
run-state persistence. Override issuance requires wallet.network grant refs plus
authority receipts and binds the Rust authority hash into the projection; the old
admission-required budget-recovery command is retired. This does not claim
terminal coding-tool budget recovery migration: retry-event materialization,
durable replay/projection, and stable SDK/IDE/CLI
protocol APIs remain required before terminal pure Rust substrate conformance.
Slice 968 moved the diagnostics repair Rust-core-required admission refusal
into the Rust daemon-core policy bridge. `DiagnosticsRepairAdmissionRequiredCore`
now emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes
`plan_diagnostics_repair_admission_required`, and the runtime daemon mounts
that runner into the diagnostics repair surface. JS still translates the
Rust-authored refusal at the HTTP edge, but no longer acts as the canonical
author for diagnostics repair decision execution, operator override state
updates, retry creation, repair decision resolution, or repair event append
refusal when the daemon-core command is configured. This does not claim terminal diagnostics
repair migration: direct Rust daemon-core repair admission/projection,
wallet.network/operator authority, Agentgres expected-head/state-root binding,
repair/operator receipts, retry-run admission, event materialization, replay,
stable SDK/IDE/CLI protocol APIs remain
required before terminal pure Rust substrate conformance.
The later diagnostics repair decision-control cut supersedes the route-facing
refusal path for decision execution and direct decision-event append: both now
require Rust daemon-core `plan_runtime_diagnostics_repair_control` and Rust
runtime-event Agentgres admission before returning accepted control truth. The
diagnostics repair decision-projection cut also supersedes the fail-closed JS
resolver: decision resolution now requires Rust daemon-core
`project_runtime_diagnostics_repair_projection`, validates the Rust projection
kind and thread/decision/gate identity, and fails closed before JS
accepted-truth resolution when Rust projection is missing or mismatched. The
follow-on replay cut removes JS decision-candidate transport for this boundary:
the daemon surface sends runtime `state_dir`, Rust replays admitted Agentgres
runtime events for repair decisions, and retired
`projection`/`decision`/`decisions`/`repair_decisions` inputs fail closed.
The diagnostics operator override state-update cut supersedes the operator
override execution refusal path: override execution now requires Rust
`plan_diagnostics_operator_override_state_update`, forwards raw canonical
operator request/decision/repair-policy context instead of JS approval verdicts,
derives approval state in Rust, and commits only the Rust-planned run projection
through Rust Agentgres run-state admission.
The diagnostics operator override direct-event cut supersedes the direct
operator-override event refusal path: direct append now requires Rust
`plan_runtime_diagnostics_repair_control` to author
`diagnostics.operator_override.event` and admits only that Rust-authored runtime
event through Rust runtime-event Agentgres admission.
The diagnostics repair retry-run cut supersedes the retry creation/direct
retry-event refusal path: retry-turn creation now requires Rust
`plan_runtime_diagnostics_repair_retry_run` before lookup, uses the Rust-authored
run-create request for the mounted run-create lifecycle surface, and admits only
a Rust-authored `diagnostics.repair_retry.created` event planned by
`plan_runtime_diagnostics_repair_control`; direct retry-event append uses the
same Rust diagnostics repair event planning and runtime-event admission path.
Slice 969 moved the run-cancel Rust-core-required admission refusal into the
Rust daemon-core policy bridge. `RunCancelAdmissionRequiredCore` now emits the
canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes `plan_run_cancel_admission_required`, and the
runtime daemon run-cancel facade uses the mounted context-policy runner to get
the Rust-authored refusal. JS still translates that refusal at the edge and
still fails closed before run-map mutation, run persistence, runtime
task/job/checklist projection rewriting, or event/receipt/artifact
materialization. This does not claim terminal run-cancel migration: direct Rust
daemon-core cancellation admission, Agentgres expected-head/state-root binding,
receipt/event materialization, persistence, replay, projection, command-transport
retirement, and stable SDK/IDE/CLI protocol APIs remain required before
terminal pure Rust substrate conformance.
The public skill/hook registry boundary now uses the positive Rust daemon-core
`project_skill_hook_registry` API. Rust owns source discovery, skill/hook record
construction, redacted hook command metadata, active set hashes, validation
counts, and route-specific `/v1/skills` and `/v1/hooks` projection records while
the mounted JS surface only forwards workspace/home request facts and validates
the returned registry kind. The older projection-required command path for this
route family is retired rather than preserved as compatibility scaffolding. This
does not claim terminal skill/hook registry migration: direct Rust
governance/catalog persistence, Agentgres-backed replay/projection storage,
wallet authority where applicable, receipt/state-root binding,
stable SDK/IDE/CLI protocol APIs remain
required before terminal pure Rust substrate conformance.
The public repository workflow boundary now uses the positive Rust daemon-core
`project_repository_workflow` API. Rust owns read-only Git discovery, sanitized
GitHub remote metadata, branch-policy decisions, issue-context defaults, PR
preview artifacts, review gate decisions, and dry-run GitHub PR create-plan
records for `/v1/repositories`, `/v1/repository-context`, `/v1/branch-policy`,
`/v1/github-context`, `/v1/pr-attempts`, `/v1/issue-context`,
`/v1/review-gate`, and `/v1/github-pr-create-plan`; the mounted JS repository
surface only forwards workspace request facts and validates the returned
projection kind. The older `RepositoryWorkflowProjectionRequiredCore` command
path is retired rather than preserved as compatibility scaffolding. This does
not claim terminal repository workflow migration: durable Agentgres-backed
repository workflow storage/replay, wallet.network authority for external
capability exits, receipt/state-root binding, and
stable SDK/IDE/CLI protocol APIs remain required before terminal pure Rust
substrate conformance.
Slice 951 retired runtime conversation-artifact public JS readback, and the
current macro cut supersedes that fail-closed read facade plus the mutation
refusal facade with Rust-owned positive projection/control. Public
`RuntimeConversationArtifactControl.listConversationArtifacts()`,
`getConversationArtifact()`, and `listConversationArtifactRevisions()` now call
Rust daemon-core `project_runtime_conversation_artifact_projection`; public
`createConversationArtifact()`, `performConversationArtifactAction()`,
`exportConversationArtifact()`, and `promoteConversationArtifact()` now call
Rust daemon-core `plan_runtime_conversation_artifact_control` and commit the
returned artifact through Rust Agentgres artifact-state admission. Read
projection and action/export/promote control send canonical request fields plus
runtime `state_dir`; Rust replays admitted `artifacts/*.json` records before
returning route truth, and rejects retired JS `artifact`/`artifacts` candidate
transport. Durable ArtifactRef/PayloadRef custody, richer mutation
storage/replay, and direct protocol APIs remain required before terminal
conformance.
Slice 952 retired runtime workspace-snapshot public JS readback. Public
`RuntimeWorkspaceSnapshotRestoreControl.listWorkspaceSnapshots()` and
`workspaceSnapshotContentPackage()` now fail closed at `workspace_snapshot.list`
and `workspace_snapshot.content_package` with
`runtime_workspace_snapshot_rust_core_required`, so JS no longer derives
workspace-snapshot projection truth from runtime-event streams or
`codingArtifacts` content packages. Direct Rust daemon-core workspace snapshot
projection over Agentgres-admitted workspace-snapshot ArtifactRef/PayloadRef
truth remains required before terminal conformance.
Slice 953 retired runtime workspace-change and managed-session public JS
inspection readback. Public
`RuntimeWorkspaceChangeControl.inspectWorkspaceChangeReviewsForThread()` and
`RuntimeManagedSessionControl.inspectManagedSessionsForThread()` now fail
closed at `workspace_change.inspect` and `managed_session.inspect` with their
Rust-core-required control errors, so JS no longer normalizes runtime-bridge
inspection envelopes, fixture fallback snapshots, workspace-change hunk
previews, or managed-session snapshots as public projection truth. The orphaned
JS inspection normalizer modules and tests were deleted. Direct Rust
daemon-core workspace-change and managed-session projection over
Agentgres-admitted truth remains required before terminal conformance.
A later managed-session positive API cut supersedes the managed-session half of
that fail-closed boundary: public managed-session inspection calls
`project_runtime_managed_session_projection` with runtime `state_dir`, Rust
derives session cards from admitted `events/*.jsonl`, public managed-session
control calls `plan_runtime_managed_session_control` with runtime `state_dir`,
Rust replays the selected current session before planning, rejects JS-supplied
control candidates, and the route admits only the Rust-authored
`managed_session.controlled` runtime event. JS remains a request/admission
client for this route family; durable managed-session record storage beyond
runtime-event replay, wallet/cTEE session authority, command transport
retirement, and stable protocol APIs remain non-terminal.
A later workspace-change positive API cut supersedes the workspace-change half
of that fail-closed boundary: public workspace-change inspection calls
`project_runtime_workspace_change_projection` with runtime `state_dir`, Rust
derives review cards from admitted `events/*.jsonl`, public workspace-change
accept/reject/rollback control calls `plan_runtime_workspace_change_control`,
Rust replays the selected current change before transition validation, rejects
JS-supplied control candidates, and the route admits only the Rust-authored
`workspace_change.controlled` runtime event. JS remains a request/admission
client for this route family; durable workspace-change record storage beyond
runtime-event replay, wallet/workspace rollback authority, command transport
retirement, and stable protocol APIs remain non-terminal.
Slice 954 retired the remaining runtime bridge thread-control JS dispatch path;
the later Rust-control cut replaced the fail-closed resume boundary with
`plan_runtime_bridge_thread_control_agent_state_update`. Runtime-service resume
now validates the Rust-planned `thread.runtime_bridge.control` agent/control
envelope, commits only that agent through Agentgres `writeAgent`, returns the
Rust thread projection, and still never calls `runtimeBridge.controlThread()` or
bridge availability checks as accepted thread-control truth. Wallet/cTEE/session
authority, durable Agentgres expected-head/state-root binding, replay, and
projection remain required before terminal runtime bridge thread/turn/control
conformance.
Slice 955 retired the remaining MCP serve direct JS dispatch path, and the
current MCP serve follow-up replaces request-envelope authorship with Rust
daemon-core `plan_runtime_mcp_serve_tool_call` before the protocol adapter calls
the mounted Rust-owned coding-tool invocation surface.
`RuntimeMcpServe.handleSingleMcpServeJsonRpc()` still owns only JSON-RPC
status/catalog parsing and planner invocation; served tool-call ids,
idempotency keys, workflow ids, and
`mcp_serve_request` now come from Rust, the old JS request helper is gone, and
the path fails closed when either the Rust planner or Rust coding-tool
invocation boundary is missing. JS still does not resolve thread agents directly
or call `invokeThreadToolAsync()` as the served tool-call admission path. Direct
Rust daemon-core MCP transport admission, wallet authority for raw MCP exits,
transport containment, replay/projection storage, and stable SDK/IDE/CLI
protocol APIs remain required before terminal MCP serve conformance.
Slice 956 retired the daemon-store `invokeThreadToolAsync()` compatibility
wrapper. The public `/v1/threads/:thread_id/tools/:tool_id/invoke` route now
calls the mounted `codingToolInvocationSurface.invokeThreadTool(store, ...)`
surface directly, preserving the current Rust workload live StepModule path
while removing the duplicate route-level JS dispatch fanout. Slice 983 then
removed the remaining daemon-store `invokeThreadTool()` wrapper and moved
post-edit diagnostics feedback dispatch onto the same mounted invocation
surface. This does not claim terminal thread-tool admission: direct Rust
daemon-core route admission, wallet authority, StepModuleRouter dispatch,
receipt/state-root binding, Agentgres truth, replay, projection,
stable SDK/IDE/CLI protocol APIs remain
required before terminal thread-tool conformance.
Slice 957 retired the daemon-store thread-control route pass-through wrappers.
The public mode/model/thinking and workspace-trust acknowledgement routes call
the mounted `RuntimeThreadControl` surface directly, so JS no longer preserves
`updateThreadMode()`, `updateThreadModel()`, `updateThreadThinking()`, or
`acknowledgeWorkspaceTrustWarning()` as duplicate store-level compatibility
wrappers. Later workspace-trust work moved warning/acknowledgement event
envelope planning to Rust `plan_workspace_trust_control_state_update` through
typed `daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate`,
admits those Rust-authored events through the Rust runtime-event Agentgres path,
and rejects the old workspace-trust state-update command operation in Rust
`command_protocol.rs`/`command_dispatch.rs`.
This still does not claim terminal thread-control or workspace-trust admission:
deeper wallet/cTEE/model-route authority, durable Agentgres projection storage,
and stable SDK/IDE/CLI protocol APIs remain required before terminal
conformance.
Slice 958 retired the daemon-store subagent route pass-through wrappers. The
public subagent list/get/result routes now call Rust
`project_runtime_subagent_projection` through the mounted
`RuntimeSubagentControl` surface, and public wait now calls Rust
`plan_runtime_subagent_control`, Rust runtime-event Agentgres admission, Rust
subagent record state-update planning, and Agentgres-backed `writeSubagent`;
public assign/cancel now use Rust `plan_runtime_subagent_control`, Rust
runtime-event Agentgres admission, Rust subagent record state-update planning,
and Agentgres-backed `writeSubagent`, with cancellation composed through Rust
run-cancel state planning; public input/resume now use Rust
`plan_runtime_subagent_control`, Rust-owned child-agent run creation, Rust
runtime-event Agentgres admission, Rust subagent record state-update planning,
and Agentgres-backed `writeSubagent`; public spawn now uses Rust
`plan_runtime_subagent_control`, Rust-owned child-agent and child-run creation,
Rust runtime-event Agentgres admission, Rust subagent record state-update
planning, and Agentgres-backed `writeSubagent`; public cancellation
propagation now uses Rust read projection, Rust propagated-cancel control
planning, Rust run-cancel state planning, Rust runtime-event Agentgres
admission, Rust subagent record state-update planning, and Agentgres-backed
`writeSubagent`, so JS no longer preserves `listSubagents()`,
`spawnSubagent()`, `waitSubagent()`, `sendSubagentInput()`,
`cancelSubagent()`, `propagateSubagentCancellation()`, `resumeSubagent()`,
`assignSubagent()`, `getSubagentResult()`, `getSubagent()`,
`subagentProjection()`, or `appendThreadSubagentControlEvent()` as daemon-store
compatibility wrappers.
This does not claim terminal subagent admission/projection: direct Rust
daemon-core route admission, wallet delegation/cancellation authority,
StepModuleRouter dispatch, Agentgres expected-head/state-root binding,
receipt/event materialization, replay, projection, command-transport
retirement, and stable SDK/IDE/CLI protocol APIs remain required before
terminal conformance.

Slice 884 retired the fail-closed `backend-lifecycle.mjs` helper module after
public backend lifecycle and backend-process supervision paths had already been
reduced to Rust-core-required backend lifecycle edge refusals. The mounted
public `ModelMountingState` backend methods now own backend health/start/stop/log
refusals, backend-process ensure/touch/start/spawn/stop refusals,
`model_mount.backend_lifecycle` metadata, and
`model_mount_backend_process_supervisor_retired` errors directly, without
importing a backend lifecycle helper. This does not claim terminal backend
lifecycle migration: direct Rust daemon-core backend lifecycle/control/projection
APIs over Agentgres-backed state, provider lifecycle execution, replay,
stable protocol APIs remain required.

Slice 885 retired the fail-closed `catalog-operations.mjs` helper module after
public catalog search orchestration, catalog-status readback, and non-search
catalog variant enrichment had already been reduced to Rust-core-required or
Rust read-projection edge refusals. Mounted `ModelMountingState` methods now own
storage-summary readback, `model_catalog_search_js_orchestrator_retired`, and
`model_catalog_variant_enrichment_js_retired` directly, without importing a
standalone catalog operations helper. This does not claim terminal catalog
migration: direct Rust daemon-core catalog search/status/variant projection APIs
over Agentgres-backed state, and stable protocol
APIs remain required.

Slice 886 retired the direct JS model-route selector and explicit endpoint
resolver from `routes.mjs`. The current mounted
`ModelMountingState.selectRoute()` and `endpointIdsForExplicitModel()` methods
now call typed `daemonCoreModelMountApi.planModelMountRouteControl`, backed by
Rust `RuntimeKernelService::plan_model_mount_route_control`, commit only
Rust-authored model_mount records, and return Rust-selected endpoint truth
before endpoint mounting, JS policy evaluation, or JS candidate scoring can run.
The remaining route-selection helpers are limited to Rust admission request
assembly, Rust-authored receipt persistence, and the typed
`daemonCoreModelMountApi.admitModelMountRouteDecision` call into Rust
`admit_model_mount_route_decision`; the old command transports for route-decision
admission and positive route-control planning are retired. This still does not claim terminal
model_route migration: direct Rust daemon-core route projection APIs over
Agentgres-backed state, stable protocol APIs, replay, and command-transport
retirement remain required before model route control reaches the pure Rust
substrate target.

Slice 887 retired the mounted JS provider-driver factory module. The
`provider-driver-factory.mjs` module and concrete-driver routing test are
deleted; `ModelMountingState.driverForProvider()` was temporarily left as a
fail-closed compatibility facade before later deletion. Lower-level driver
modules remain only as explicitly retired edge-adapter tests or fail-closed
transport stubs until direct Rust daemon-core provider execution/control APIs
replace them. This does not claim terminal provider migration: direct Rust
daemon-core provider transports, lifecycle, inventory, projection,
Agentgres-backed replay, stable protocol APIs, and command-transport retirement
remain required before provider execution reaches the pure Rust substrate
target.

Slice 888 retired the LM Studio driver's nested OpenAI-compatible adapter. The
fail-closed `LmStudioModelProviderDriver` no longer imports or constructs
`OpenAICompatibleModelProviderDriver`, no longer stores `this.openAi` or
`this.state`, and remains a pure Rust-core-required refusal stub for LM Studio
health, inventory, lifecycle, load/unload, invoke, and stream-invoke paths.
This removes one more lower-level JS driver composition point after the mounted
provider-driver factory was retired. Terminal provider migration still requires
direct Rust daemon-core LM Studio/provider transports, lifecycle, inventory,
projection, Agentgres-backed replay, stable protocol APIs, and
command-transport retirement.

Slice 889 retired the vLLM and llama.cpp backend-driver provider projection
shims. The fail-closed backend drivers no longer store `this.state`, expose
`providerWithBackendBaseUrl()`, promote provider `baseUrl` or blocked/configured
status from JS backend records, or project loaded-instance truth from
`state.listInstances()`/backend-process snapshots. vLLM and llama.cpp
`listLoaded()` now fail closed at the provider HTTP transport retirement
boundary until direct Rust daemon-core provider inventory/projection APIs own
Agentgres-backed loaded-instance truth. Terminal provider migration still
requires direct Rust daemon-core provider transports, lifecycle, inventory,
projection, Agentgres-backed replay, stable protocol APIs, and
command-transport retirement.

Slice 890 deleted the remaining hosted/nonlocal JS provider-driver modules.
`provider-openai-compatible-driver.mjs`, `provider-openai-backend-drivers.mjs`,
`provider-ollama-driver.mjs`, and `provider-lm-studio-driver.mjs` are absent
along with their focused tests, rather than preserved as fail-closed
compatibility surfaces. The mounted provider-driver factory already fails
closed before driver allocation, and hosted/nonlocal provider execution,
inventory, lifecycle, and stream/invoke behavior must now re-enter only through
direct Rust daemon-core model_mount/provider APIs when those APIs are verified.
Terminal provider migration still requires direct Rust daemon-core provider
transports, lifecycle, inventory, projection, Agentgres-backed replay, stable
protocol APIs, and command-transport retirement.

Slice 891 retired provider driver-kind inference from the JS model_mount
facade. The JS helper layer no longer exports a kind-to-driver mapper or
driver-name fallback helper, provider invocation requests carry only explicit
provider or endpoint `driver` fields, and hosted/non-migrated provider failure
details report `provider_driver: null` when no explicit driver was admitted.
This prevents deleted hosted driver modules from being reintroduced as implicit
compatibility semantics and keeps provider execution/control pointed at direct
Rust daemon-core model_mount/provider APIs. Terminal provider migration still
requires direct Rust daemon-core provider transports, lifecycle, inventory,
projection, Agentgres-backed replay, stable protocol APIs, and
command-transport retirement.

Slice 892 deleted the leftover provider invocation-retirement and HTTP
transport wrappers. `provider-invocation-retirement.mjs`,
`provider-transport.mjs`, and `provider-transport.test.mjs` are absent rather
than preserved as fail-closed compatibility surfaces after hosted/nonlocal JS
drivers, provider HTTP request shaping, retry probes, and driver-name inference
were retired. Public provider execution still fails closed through the mounted
daemon facades and Rust provider-result admission checks, but there is no
standalone JS provider invocation/HTTP transport module for future code to
re-enter. Terminal provider migration still requires direct Rust daemon-core
provider transports, lifecycle, inventory, projection, Agentgres-backed replay,
stable protocol APIs, and command-transport retirement.

Slice 893 deleted the final provider transport-policy remnant.
`provider-transport-policy.mjs` and `provider-transport-policy.test.mjs` are
absent after the HTTP transport wrapper deletion, so timeout, retry, stream,
and provider-health transport policy no longer has a standalone JS
compatibility module to re-enter. Public provider health/control still fails
closed through mounted daemon facades until direct Rust daemon-core provider
APIs own the surface. Terminal provider migration still requires direct Rust
daemon-core provider transports, lifecycle, inventory, projection,
Agentgres-backed replay, stable protocol APIs, and command-transport
retirement.

Slice 894 deleted the retired private JS OAuth credential custody helper.
`oauth-credential-provider.mjs` and `oauth-credential-provider.test.mjs` are
absent rather than preserved as a fail-closed compatibility wrapper after the
mounted OAuth facades moved to direct Rust-core-required refusals and
`fetchOAuthToken()` moved to the Rust daemon-core OAuth custody boundary. OAuth
start/callback/exchange/refresh/revoke and auth-header resolution can no longer
re-enter a private JS credential helper for vault binding, token transport,
refresh, revoke, or access-header shaping. Terminal catalog-provider custody
migration still requires direct Rust daemon-core OAuth control, wallet/cTEE vault
custody, Agentgres-backed OAuth/session projection, stable protocol APIs, and
command-transport retirement.

Slice 895 deleted the leftover `backend-processes.mjs` lookup/snapshot wrapper.
`backend-processes.mjs` and `backend-processes.test.mjs` are absent rather than
kept as a standalone compatibility module after backend process supervision had
already moved to mounted Rust-core-required lifecycle refusals and Rust
`model_mount` backend-process planning. The mounted model_mount facade now owns
missing-backend lookup metadata and process-snapshot normalization directly, so
backend process lookup, snapshot shaping, lifecycle refusal, and Rust planner
transport no longer have a reusable JS backend-process helper to re-enter.
Terminal backend lifecycle migration still requires direct Rust daemon-core
process control, Agentgres-backed backend lifecycle projection/replay, stable
protocol APIs, and command-transport retirement.

Slice 896 deleted the provider-registry dependency-injection binding wrapper.
`provider-registry-bindings.mjs` and `provider-registry-bindings.test.mjs` are
absent rather than preserved as a standalone compatibility layer over the
canonical provider registry helpers. The mounted model_mount facade now imports
`hostedProvider()`, `optionalString()`, and `requiredString()` from the
canonical provider registry directly. The later Slice 917 public-provider
projection-helper deletion means provider public/vault envelope shaping is no
longer a provider-registry responsibility. Terminal provider control/projection
migration still requires direct Rust daemon-core provider configuration,
wallet/cTEE custody projection, Agentgres-backed replay, stable protocol APIs,
and command-transport retirement.

Slice 897 deleted the retired LM Studio public-discovery helper tail. The
default-discovery module no longer exports `discoverLmStudioProvider()`,
`discoverLmStudioArtifacts()`, or `pruneLmStudioPublicProjectionRecords()`;
mounted model_mount no longer exposes matching pass-through methods; default
seeding no longer calls the retired prune no-op; and local-system probes no
longer retain the dead LM Studio list parser, process parser, artifact projector,
or public-CLI environment toggle. Terminal provider inventory/projection
migration still requires direct Rust daemon-core inventory/projection APIs over
Agentgres-admitted provider and model topology truth.

Slice 898 deleted the final LM Studio load-option public-CLI argument helper.
`lmStudioLoadOptionArgs()` is no longer exported from `load-policy.mjs`, and the
test that preserved stable `lms` CLI flags for GPU/context/parallel/TTL/identifier
options is removed. Canonical load options remain as Rust-boundary request data;
JS no longer keeps an LM Studio-specific CLI argument shaper for retired public
CLI transport.

Slice 899 deleted the orphan per-record model_mount record-state commit
wrappers. `conversation-record-state.mjs`, `mcp-server-record-state.mjs`,
`model-artifact-record-state.mjs`, `model-download-record-state.mjs`,
`model-endpoint-record-state.mjs`, `model-instance-record-state.mjs`, and
`oauth-record-state.mjs` are absent rather than preserved as standalone
compatibility modules over the shared Rust Agentgres commit gate. The live
facades still fail closed before JS receipt, map, filesystem, OAuth, MCP,
conversation, artifact, endpoint, download, or instance record-state mutation;
the remaining `record-state-commits.mjs` path is only the canonical Rust
Agentgres commit transport used by verified projection persistence until direct
Rust daemon-core APIs remove that transport layer too.

Slice 900 deleted the final standalone provider-driver helper module.
`provider-driver-helpers.mjs` and `provider-driver-helpers.test.mjs` are absent
rather than preserved as compatibility scaffolding for coalescing, variance, or
provider-kind driver/backend inference. The only still-live backend-id default
used by load-estimate projection is now private owner-local code in
`model-mounting.mjs`; provider invocation continues to require explicit
provider/endpoint `driver` fields and no longer carries a reusable JS helper
surface that could reintroduce hosted driver inference or retired camelCase
coalescing behavior.

Slice 901 deleted the unused local runtime-engine helper tail. The remaining
`local-runtime-engines.mjs` module keeps only migration-time llama.cpp binary
discovery and library-path materialization used by current backend registry
seeding; it no longer exports `llamaCppGpuLayersArg()` or
`backendBindAddress()`, and its focused test no longer preserves a public
product GPU-mode-to-llama.cpp flag contract. Terminal runtime-engine migration
still requires direct Rust daemon-core runtime-engine preference/profile,
projection, process-planning, local runtime materialization, Agentgres replay,
stable protocol APIs, and command-transport retirement.

Slice 902 deleted the retired catalog-entry materializer module.
`catalog-entries.mjs` and `catalog-entries.test.mjs` are absent rather than
preserved as a fail-closed compatibility wrapper for fixture catalog entries,
local manifest parsing, Hugging Face entry shaping, Ollama artifact entry
projection, filter matching, or legacy variant selection metadata. Mounted
catalog search now returns the Rust `catalog_search` read projection, while
variant enrichment still fails closed at its Rust daemon-core projection
boundary; JS no longer retains a standalone catalog entry materialization
library for retired catalog surfaces to re-enter.

Slice 903 deleted the orphan workflow-node response helper module.
`workflow-node.mjs` and `workflow-node.test.mjs` are absent rather than
preserved as a standalone native-response compatibility surface for capability
mapping, workflow-kind mapping, or route-decision envelope shaping. Mounted
workflow-node execution already fails closed at the Rust daemon-core
`model_mount.workflow_node.execute` boundary before JS route, MCP, receipt-gate,
or model dispatch; OpenAI-compatible response projection retains the remaining
canonical snake_case route-decision coverage without a separate model_mount
workflow-node helper.

Slice 904 deleted the standalone server-control facade helper module.
`server-control.mjs` and `server-control.test.mjs` are absent rather than
preserved as a server-state/log compatibility wrapper. Mounted
`ModelMountingState` methods now own server-control Rust-core-required
refusals directly, including the formerly dangling `recordServerOperation()`
surface, while the dedicated `server_status` read projection keeps only its
narrow primitive migration input inside the direct model_mount read-projection client. JS still
does not write `server-state.json`, append local server logs, synthesize server
control receipts, or project provider/backend status as server truth.

Slice 905 deleted the orphan catalog-provider projection helper module.
`catalog-projections.mjs` and `catalog-projections.test.mjs` are absent rather
than preserved as product/config/auth projection compatibility builders.
Catalog-provider ports keep only private port-local product-safe health defaults
for gated/retired search status, while public catalog-provider configuration,
auth-header, OAuth, search, status, and variant projection truth remains
fail-closed or Rust-planned until direct Rust daemon-core catalog-provider APIs
replace the migration transport.

Slice 906 deleted the dead catalog download policy helper cluster.
`catalog-helpers.mjs` no longer exports `catalogDownloadRisk()`,
`normalizeDownloadPolicy()`, or `catalogApprovalDecision()` as a parallel JS
transfer-policy/risk/recommendation layer. The mounted catalog import/download
facades already fail closed at the Rust daemon-core catalog/download boundary,
so JS keeps only the still-called local artifact/import metadata helpers until
direct Rust daemon-core catalog/download admission owns transfer policy,
receipts, record-state, and projection.

Slice 907 deleted the orphan catalog download materializer module.
`download-helpers.mjs` is absent rather than preserved as a dormant HTTP,
partial-file, retry, checksum, or fixture-download execution path. The mounted
catalog import/download facades no longer import the materializer helpers, so
catalog/download filesystem and network transfer semantics remain unavailable
from JS until direct Rust daemon-core catalog/download admission owns the path.

Slice 908 deleted the dormant catalog import materializer helper tail.
`catalog-helpers.mjs` no longer exports `normalizeImportMode()`,
`importTargetPath()`, or `materializeImportArtifact()` as a local import
filesystem execution path. The mounted artifact import facade already fails
closed at the Rust daemon-core artifact/endpoint boundary, and Slice 941 later
removed the reusable local model file listing/scoring/quantization helper
exports from `catalog-helpers.mjs`; JS keeps only the destructive-confirmation
alias guard there while local artifact inspection keeps private file scoring
for non-authoritative request inspection.

Slice 909 removed the dormant catalog-provider port search surfaces.
Catalog-provider ports no longer expose `search` closures or retired
search-result builders such as `retiredLiveCatalogSearchResult()`,
`retiredLocalManifestCatalogSearchResult()`, or
`retiredFixtureCatalogSearchResult()`. Public catalog search now reaches the
Rust provider-inventory replay projection before JS provider iteration, so
provider ports now retain only health/gating metadata while hosted/external,
local-manifest, fixture, and Ollama catalog enrichment remain non-terminal.

Slice 910 deleted the catalog-provider port and registry helper surface.
`catalog-provider-ports.mjs`, `catalog-provider-ports.test.mjs`,
`catalog-registry.mjs`, and `catalog-registry.test.mjs` are absent, and the
mounted `catalogProviderPorts()` method is gone from `ModelMountingState`.
Catalog-provider configuration, OAuth, catalog status, and catalog search
surfaces already fail closed or route to Rust read-projection boundaries, so JS
no longer keeps local provider-port ordering, health-status merge, or
`catalogProviderStatus()` compatibility helpers as a dormant catalog authority
shape.

Slice 911 deleted the remaining catalog-provider source/auth shaping and OAuth
boundary helper surface from JS. `catalog-provider-config.mjs` now contains the
catalog-provider-control Rust client helper, Agentgres record-state commit
adapter, and defensive missing-planner error only; `catalog-provider-config.test.mjs`,
`oauth-boundary.mjs`, and `oauth-boundary.test.mjs` are absent. JS no longer
preserves `catalogProviderRuntimeMaterialFromBody()`,
`catalogProviderAuthConfig()`, `catalogProviderAuthHeaders()`,
`catalogAuthorizationHeaderValue()`, `fetchOAuthToken()`,
`parseOAuthTokenResponse()`, `publicOAuthSession()`, `publicOAuthState()`,
PKCE helpers, OAuth vault-ref helpers, or OAuth boundary projection helpers as
compatibility scaffolding. Direct Rust daemon-core catalog-provider control,
OAuth custody, auth-header resolution, Agentgres-backed truth, and stable
protocol APIs still remain required before this surface reaches terminal pure
Rust conformance.

Slice 912 deleted the standalone runtime-engine compatibility helper and moved
the public mutation refusal boundary onto `ModelMountingState` itself.
`runtime-engines.mjs` and `runtime-engines.test.mjs` are absent; the mounted
`selectRuntimeEngine()`, `updateRuntimeEngine()`, and
`removeRuntimeEngineOverride()` methods fail closed directly with
`model_mount_runtime_engine_rust_core_required` before JS can create
runtime-engine receipts, mutate preference/profile maps, write projection state,
or preserve helper-level readback builders. Public runtime-engine
list/detail/default-load/preference/profile reads continue to call
`plan_model_mount_read_projection` through the direct model_mount read-projection client with
narrow Rust-planned request state. Direct Rust daemon-core runtime-engine
preference/profile/projection APIs, Agentgres-backed truth, receipt/state-root
binding, replay, stable protocol APIs, and command-transport retirement remain
required before runtime-engine control reaches terminal pure Rust conformance.

Slice 913 deleted the final local provider driver adapter module.
`provider-local-drivers.mjs` and `provider-local-drivers.test.mjs` are absent
rather than preserved as Rust-planning wrapper classes for native-local or
fixture health, inventory, lifecycle, direct invoke, or stream invoke. The
mounted `driverForProvider()` factory is now absent, local provider invocation
and stream invocation continue through Rust `model_mount` admission/execution
paths, and provider health/inventory/load/unload public facades remain mounted
Rust-core-required boundaries until direct Rust daemon-core provider
control/projection APIs own those surfaces. Direct Rust daemon-core provider
transports, inventory, lifecycle control, Agentgres-backed truth, replay, stable
protocol APIs, and command-transport retirement remain required before provider
execution/control reaches terminal pure Rust conformance.

Slice 914 deleted the orphan JS model-capability materializer.
`model-capability.mjs` and `model-capability.test.mjs` are absent instead of
preserved as a daemon-side fallback capability builder after public
`listModelCapabilities()` and broad model_mount projection reads moved through
Rust `plan_model_mount_read_projection`. The SDK still declares the canonical
snake_case protocol contract, but the daemon no longer carries a self-tested JS
implementation that can reconstruct route/provider/artifact readiness as public
truth. The follow-on capability projection cut moved `listModelCapabilities()`
to Rust `model_mount/read_projection/topology.rs` over runtime `state_dir`
replay: Rust derives canonical `ioi.model-capability.v1` records from admitted
`model-routes`, `model-route-endpoint-resolutions`, `model-provider-inventory`,
and `model-instances` records, filters JS-authored records, emits explicit
candidate readiness/evidence, and no longer returns a default empty list for
admitted route truth. richer wallet/cTEE authority
binding, stable protocol APIs, and broader hosted/provider materialization still
remain before capability projection reaches terminal pure Rust conformance.

Slice 915 deleted the orphan JS model-instance lifecycle planning facades while
leaving the Rust bridge and receipt-binding guards in place. The helper module
`model-instance-lifecycle.mjs` no longer exports
`planModelMountInstanceLifecycleForMigratedProvider()`,
`modelMountInstanceLifecycleRequiresRust()`, or
`modelMountInstanceLifecycleFields()`. The mounted
`ModelMountingState.planModelMountInstanceLifecycle()` method is now a
temporary positive Rust client over
`ModelMountCore.planInstanceLifecycle()` for public load/unload,
not an authority-bearing JS planner. Direct instance lifecycle planning belongs
to Rust `model_mount` through `plan_model_mount_instance_lifecycle`; JS may only
assemble canonical request facts, commit the Rust-authored transition record
through Agentgres, return committed Rust lifecycle records, or validate already
admitted lifecycle receipts before store persistence. Direct Rust daemon-core
Agentgres-backed projection/replay, stable protocol APIs, and
command-transport retirement remain required before instance lifecycle reaches
terminal pure Rust conformance.

Slice 916 retired the remaining JS route-control record and route-selection
receipt builder facades. `routes.mjs` no longer exports `upsertRouteRecord()`,
`routeSelectionReceipt()`, `routeSelectionReceiptForState()`,
`modelMountRouteDecisionRequestForSelection()`, or
`persistModelRouteSelectionState()`. Public route upsert/test and mounted
route-selection methods still reject retired request aliases, then call the
positive Rust daemon-core route-control planner and commit only Rust-authored
records; JS no longer normalizes route records, allocates route-selection
receipt ids, constructs `ModelMountRouteDecisionRequest` payloads, or persists
accepted route-selection receipts from local decision truth. Rust
route-selection/endpoint-resolution replay now exists through the model_mount
read-projection boundary. The route-control command transport is now retired;
broader wallet/cTEE route authority and stable protocol APIs remain required
before route control reaches terminal pure Rust conformance.

Slice 917 deleted the canonical provider-registry public-provider projection
helper. `provider-registry.mjs` no longer exports `publicProvider()`, and the
dedicated provider-registry tests plus mounted provider-operation fixtures no
longer preserve JS public-provider/vault-boundary redaction expectations.
Public provider list/readback continues through Rust `plan_model_mount_read_projection`
kinds, while mounted provider mutation facades remain fail-closed before JS
provider-map writes or JS provider-control receipts. Direct Rust daemon-core
provider projection over Agentgres/wallet/cTEE admitted truth, stable protocol
APIs, and command-transport retirement remain required before provider
projection/control reaches terminal pure Rust conformance.

Slice 918 retired the JS provider-auth header materialization facade.
`provider-auth.mjs` no longer exports `providerAuthHeaders()`,
`providerAuthorizationHeaderValue()`, `assertProviderVaultBoundary()`,
`providerHasVaultRef()`, `normalizeProviderAuthScheme()`, or
`normalizeProviderAuthHeaderName()`, and the mounted model_mount facade no
longer imports those helpers. JS still rejects plaintext provider secrets,
enforces canonical vault-ref request fields, and performs provider-kind vault-ref
preflight before the fail-closed provider-control boundary, but it no longer
resolves provider vault material or assembles outbound provider auth headers.
Direct Rust daemon-core wallet/cTEE provider auth APIs, Agentgres-backed
provider truth, stable protocol APIs, and command-transport retirement remain
required before provider auth/control reaches terminal pure Rust conformance.

Slice 919 retired the dead JS provider-protocol fixture, tokenizer, request-text,
usage-normalization, JSON-parse, truncation, and limit-normalization helpers.
`provider-protocol.mjs` now exports only `estimateTokens()`, and the mounted
model_mount facade no longer imports the provider-protocol module at all. The
remaining `estimateTokens()` fallback exists only inside provider-result
admission-request assembly for Rust-executed provider outputs that do not yet
carry explicit token counts. Direct Rust provider-result envelopes and token
accounting still need to remove that final JS fallback before provider
invocation/result reaches terminal pure Rust conformance.

Slice 929 deleted the final `provider-protocol.mjs` token-count fallback.
Provider-result admission-request assembly now requires Rust/provider result
`token_count` and fails closed when it is missing or internally inconsistent, so
the JS edge can no longer estimate usage as duplicate provider-result truth.
Direct Rust provider transports, stable protocol APIs, and command-transport
retirement remain required before provider invocation/result reaches terminal
pure Rust conformance.

Slice 920 deleted the orphan JS model-instance lifecycle guard module.
`model-instance-lifecycle.mjs` is absent, and the remaining receipt-binding
issue detection for already admitted Rust-bound instance lifecycle evidence now
lives inside `receipt-write-guards.mjs` beside the receipt persistence guard
that uses it. Public load/unload now uses Rust instance-lifecycle planning and
Rust Agentgres model-instance record commits; loaded-instance idle eviction,
duplicate coalescing, and explicit supersede now use Rust instance-lifecycle
planning and Rust Agentgres model-instance record commits as well. Agentgres
projection/replay, stable protocol APIs, and command-transport retirement
remain required before instance lifecycle reaches terminal pure Rust
conformance.

Slice 921 deleted the standalone JS fixture-policy compatibility wrapper.
`fixture-policy.mjs` is absent, and the remaining disabled-internal-fixture
cleanup predicates now live privately inside `default-discovery.mjs`. Default
seeding can still remove internal fixture artifacts/endpoints/instances when
fixture defaults are disabled, but JS no longer exposes a separate reusable
fixture policy module or dependency-injected predicate surface that could be
mistaken for model-mount inventory/projection authority. Slice 942 later
removed native fixture artifact file materialization from the same module, so
default discovery no longer writes fake native-local model files as storage
truth. Direct Rust daemon-core provider inventory, catalog/default-discovery
policy, Agentgres topology truth, stable protocol APIs, and command-transport
retirement remain required before model-mount discovery and inventory reach
terminal pure Rust conformance.

Slice 922 retired daemon-side StepModule shadow/gated backend selection.
`createStepModuleRunnerFromEnv()` now accepts only `rust_workload_live`;
explicit `daemon_js`, `rust_workload_shadow`, or `rust_workload_gated` selections
fail closed. The daemon runner reports live mode and live workflow projection by
default, so shadow/gated comparison modes cannot be selected from the JS runtime
edge as split-brain execution fallbacks. The `ioi-step-module-bridge` command
path remains migration transport only; direct Rust daemon-core StepModuleRouter
APIs, Agentgres admission, replay, projection, stable protocol APIs, and
command-transport retirement remain required before the StepModule substrate
reaches terminal pure Rust conformance.

Slice 923 retired daemon-side StepModule backend selector configuration.
`IOI_STEP_MODULE_BACKEND`, constructor `backend` options, and the
`normalizeStepModuleBackend()` helper path are absent from the runtime-daemon
runner. `createStepModuleRunnerFromEnv()` constructs a live Rust workload runner
by construction; any explicit backend selection, including the formerly accepted
`rust_workload_live` value, fails closed with
`step_module_backend_selection_retired`. This removes the remaining JS edge
configuration surface that could encode StepModule backend selection as a local
compatibility switch. The `ioi-step-module-bridge` command path remains
migration transport only; direct Rust daemon-core StepModuleRouter APIs,
Agentgres admission, replay, projection, stable protocol APIs, and
command-transport retirement remain required before the StepModule substrate
reaches terminal pure Rust conformance.

## Part II: Target Execution Model

This part defines the desired ownership shape. It says which layer owns each
runtime responsibility, how the Rust/WASM substrate sits under the daemon, and
why the mature end state is a Rust daemon core rather than a permanent JS
execution substrate.

### Unified stack

```text
Hypervisor IDE / CLI / SDK
  compose, inspect, approve, replay, package, and govern work

Hypervisor Daemon
  execution owner, authority/effect boundary, local product control plane;
  implementation may begin as Node/JS facade, but mature daemon core should
  consolidate in Rust once the ABI and workload bridge prove parity

Default Harness Profile
  daemon-executed loop-native orchestration profile

StepModuleRouter
  canonical bridge from daemon steps to execution backends

Execution backends
  direct daemon-native tools
  Rust/WASM service modules
  Rust workload container jobs
  model/inference mounts
  cTEE Private Workspace actions
  verifier modules
  external AIIP/capability exits

Agentgres
  admitted operations, object heads, run/task state, receipts, artifact refs,
  archive refs, projections, state roots, delivery state, replay/restore truth

wallet.network
  authority grants, approvals, secrets, leases, declassification,
  capability exits, revocation

Storage backends
  payload bytes only, behind Agentgres-governed refs

IOI L1 / compatible app chains
  sparse public/economic/cross-domain settlement by trigger only
```

### Authority owner map

| Responsibility | Authoritative owner | Notes |
| --- | --- | --- |
| User/operator UX | Hypervisor IDE / CLI / SDK | Requests, displays, composes, steers, inspects. Does not own execution semantics. |
| Execution semantics | Hypervisor Daemon | The daemon decides what can cross an effect boundary. |
| Orchestration profile | Default Harness Profile | Configures loop-native work under daemon ownership. |
| Step/module execution backend | Rust/WASM workload/kernel substrate | Authoritative backend for admitted module execution after migration. |
| Tool approval and effect gate | Hypervisor Daemon + wallet.network | Daemon gates; wallet.network issues authority grants/approval receipts. |
| Canonical operational truth | Agentgres | Accepted operations, refs, heads, state roots, projections, replay/restore truth. |
| Semantic memory surface | Agent Wiki / ioi-memory | Knowledge/retrieval plane. Durable authoritative mutations are admitted into Agentgres. |
| Private workspace custody | Private Workspace backed by cTEE | No-plaintext-custody routing and custody proofs. |
| Payload bytes | Storage backends | Local disk, S3, Filecoin, CAS/IPFS, object stores, provider/customer blobs. |
| Interop packets | AIIP | Bounded autonomous-work interop between domains/runtimes. |
| Public/economic settlement | IOI L1 / compatible app chains | Triggered by marketplace, rights, public roots, disputes, interop, reputation, or explicit policy. |

### Runtime layering invariant

The Rust/WASM substrate must not become a second runtime beside the daemon.

Correct:

```text
Hypervisor Daemon
  -> StepModuleRouter
     -> Rust/WASM workload/kernel backend
```

Incorrect:

```text
Hypervisor Daemon runtime
Rust/WASM runtime
Both independently decide authority and state truth
```

The daemon owns the authority/effect boundary. The Rust/WASM substrate executes
admitted module work and returns receipt-bound results.

### Rust core end state

This guide rejects a blind first-step rewrite. It does not reject Rust as the
best long-term daemon core.

The mature target should be:

```text
Hypervisor Daemon Rust Core
  owns authority gates, StepModuleRouter, workload client, Agentgres admission,
  receipt emission, cTEE custody enforcement, resource control, IPC, replay,
  and state-root validation

Hypervisor Product/API Facade
  serves IDE/SDK/HTTP transition surfaces, developer ergonomics, workflow
  projection shaping, and short-lived migration adapters
```

Migration doctrine:

```text
Port by extraction, not by rewrite.
```

That means:

1. Define the Step/Module ABI while the JS daemon still works.
2. Wrap JS tool steps in the ABI.
3. Shadow-route selected steps through Rust workload/kernel backends.
4. Promote stable steps to gated/live Rust execution.
5. Move authority, routing, receipt, state-root, and cTEE enforcement into a
   Rust daemon core.
6. Shrink JS to product/API transition glue, then remove it from each
   authoritative path once the Rust core has parity.

The performance end shape is Rust-heavy because the hot paths belong close to
the kernel:

- workload IPC and shared-memory/rkyv data plane;
- StepModuleRouter dispatch;
- authority and policy evaluation;
- receipt and state-root binding;
- cTEE custody checks;
- model/workload routing;
- resource leases and cancellation;
- replay and conformance checks.

The product surface can remain TypeScript/JS where it improves UI velocity and
ecosystem integration, but it should not remain the final owner of hot-path
execution or canonical transition admission.

### Target Rust core module layout

The Rust core should be split by owner boundary, not by accident of route
history. A target crate or module tree should roughly preserve this shape:

| Core module | Owns | Must not own |
| --- | --- | --- |
| `authority` | policy evaluation, grants, leases, approval binding, wallet.network handoff | IDE rendering or product copy |
| `step_router` | `StepModuleInvocation` validation, backend selection, mode promotion, idempotency | backend-specific execution internals |
| `workload_client` | workload gRPC, shared-memory/rkyv handles, WASM/job invocation, cancellation | authority decisions |
| `model_mount` | model route selection, model invocation envelopes, model receipts, provider/TEE/cTEE route metadata | private workspace plaintext |
| `ctee` | custody type checks, plaintext-free runtime mount validation, leakage profiles, declassification gates | generic storage backend policy |
| `receipt_binder` | receipt emission, receipt roots, operation/result binding, output ownership receipts | Agentgres admission policy |
| `agentgres_admission` | operation proposal, expected heads, state-root validation, projection checkpoints | raw payload byte custody |
| `projection` | workflow node projections, replay metadata, IDE/SDK response shaping | accepted truth mutation |
| `conformance` | positive and negative conformance checks, replay tests, route-family retirement checks | product feature behavior |

This layout is not a naming mandate. It is an ownership mandate. If a module
mixes route handling, authority, execution, receipt binding, projection shaping,
and tests, the guide has not been carried out cleanly.

### Facade retirement end state

After Rust daemon core parity is proven, the JS daemon facade should be retired
from authoritative runtime paths.

Keep JS/TS where it is a product or developer-experience advantage:

```text
Hypervisor IDE
web product surfaces
SDK ergonomics and examples
workflow authoring UI
non-authoritative clients
documentation fixtures
```

Remove JS/TS from authoritative daemon hot paths:

```text
execution semantics
StepModuleRouter
authority gates
Agentgres admission
receipt/state-root binding
cTEE custody enforcement
workload IPC
model/workload routing
resource leases and cancellation
replay/conformance
```

Target:

```text
Hypervisor Daemon = Rust
Hypervisor kernel/workload = Rust/WASM
Hypervisor IDE = TS/React or equivalent product UI
Hypervisor SDK = protocol bindings over Rust/core APIs
```

The JS facade is a migration scaffold, not a permanent authority layer. This is
an alpha-stage system with no downstream compatibility promise. Once the Rust
core owns the route family and the IDE/SDK can talk to it through stable
protocol APIs, the corresponding JS route should be removed or demoted into a
non-authoritative client adapter. Do not preserve legacy shims merely to keep old
callers alive.

## Part III: Unified Step/Module Contract

This part is the implementation hinge. It defines the ABI that lets one
daemon-owned loop step route to JS migration paths, Rust/WASM modules, workload
jobs, model mounts, cTEE actions, verifiers, or external capability exits
without changing the workflow graph or authority model.

### Purpose

The Step/Module ABI is the canonical bridge between product-daemon loop steps and
kernel/workload execution.

It must let a daemon step become any of these without changing the user-facing
workflow graph:

- direct daemon-native tool;
- Rust/WASM service module invocation;
- workload container job;
- model/inference mount call;
- cTEE Private Workspace action;
- verifier step;
- external AIIP or capability exit.

### Canonical lifecycle

```text
ModelPass or deterministic planner
  -> ActionProposal
  -> GateResult
  -> ModuleInvocation
  -> backend execution
  -> ExecutionResult
  -> NormalizedObservation
  -> Receipt / ArtifactRef / PayloadRef / state-root update
  -> Agentgres operation admission or rejection
  -> workflow compositor projection update
  -> model re-entry or terminal output ownership
```

### Object shape

```yaml
StepModuleInvocation:
  schema_version: ioi.step_module_invocation.v1
  invocation_id: invocation://...
  run_id: run:...
  task_id: task:...
  thread_id: thread:... | null
  workflow_graph_id: workflow:... | null
  workflow_node_id: node:... | null
  context_chamber_ref: chamber:... | null

  action_proposal_ref: action:...
  gate_result_ref: gate:...
  module_ref:
    kind:
      daemon_native_tool |
      rust_wasm_service_module |
      workload_job |
      model_mount |
      private_workspace_ctee_action |
      verifier |
      aiip_capability_exit
    id: string
    version: semver_or_hash
    manifest_ref: artifact://... | ai://... | module://... | null

  actor:
    actor_id: worker:... | service_engine:... | runtime:... | verifier:...
    runtime_node_ref: node://...

  authority:
    authority_grant_refs:
      - grant://...
    policy_hash: sha256:...
    primitive_capabilities:
      - prim:file.read
      - prim:model.invoke
    authority_scopes:
      - scope:repo.read
      - scope:agentgres.operation
    approval_ref: approval://... | null

  input:
    input_hash: sha256:...
    expected_schema_ref: schema://...
    context_refs:
      - ctx:...
    artifact_refs:
      - artifact://...
    payload_refs:
      - payload://...
    state_root_before: sha256:... | null
    projection_watermark: domain_seq:... | null
    data_plane_handle:
      region_id: string
      offset: integer
      length: integer
      codec: rkyv | raw | protobuf | json | none
      required: false

  custody:
    privacy_profile:
      public | internal | redacted | private_workspace_ctee | tee_confidential
    plaintext_policy:
      node_plaintext_allowed: boolean
      declassification_required: boolean
    custody_proof_ref: artifact://... | null
    leakage_profile_ref: artifact://... | null

  execution:
    backend:
      daemon_js | rust_wasm | workload_grpc | model_mount | ctee_operator | aiip
    idempotency_key: string
    deadline_ms: integer
    resource_lease_ref: lease://... | null
    retry_policy_ref: policy://... | null
```

```yaml
StepModuleResult:
  schema_version: ioi.step_module_result.v1
  invocation_id: invocation://...
  status:
    success | failure | partial | blocked | denied | timeout | invalid
  execution_result_ref: result:...
  normalized_observation_ref: observation:...
  receipt_refs:
    - receipt://...
  artifact_refs:
    - artifact://...
  payload_refs:
    - payload://...
  agentgres_operation_refs:
    - agentgres://operation/...
  state_root_after: sha256:... | null
  resulting_head: sha256:... | null
  workflow_projection:
    workflow_graph_id: workflow:...
    workflow_node_id: node:...
    component_kind: string
    status: projected | shadow | gated | live | blocked | failed
    attempt_id: string
    evidence_refs:
      - artifact://...
    receipt_refs:
      - receipt://...
  next:
    model_reentry_required: boolean
    verifier_required: boolean
    output_ownership_candidate: boolean
    blocker_ref: blocker:... | null
```

### Backend semantics

`execution.backend` describes how the step executes during a given slice. It is
not an ownership claim.

| Backend | Terminal status | Meaning |
| --- | --- | --- |
| `daemon_js` | migration-only | Existing JS daemon execution path wrapped in the Step/Module contract. Invalid after terminal conformance for authoritative work. |
| `rust_wasm` | terminal | WASM service module execution through the Rust kernel/workload substrate. |
| `workload_grpc` | terminal | Workload container job through the Rust control plane and shared data plane. |
| `model_mount` | terminal | Daemon-owned model/inference route mediated by the Rust core after extraction. |
| `ctee_operator` | terminal | Private Workspace/cTEE route with custody checks and leakage/declassification receipts. |
| `aiip` | terminal | External interop or capability exit through bounded autonomous-work packets. |

Terminal conformance forbids `daemon_js` from appending accepted operations,
issuing authoritative receipts, deciding authority, enforcing cTEE custody, or
acting as the execution substrate for migrated route families.

### Backend routing table

| Step kind | Preferred backend | When to use | Required output |
| --- | --- | --- | --- |
| Low-risk daemon read | direct daemon-native tool | Existing JS path is stable and cheap. | NormalizedObservation + receipt refs. |
| Mutating file/tool step | Rust/WASM service module or workload job after migration | Consequential tool mutation needs state-rooted execution and replay. | Receipt + state-root delta + artifact refs. |
| Test/lint/build verification | workload job or verifier module | Deterministic evidence-producing work. | VerificationReceipt + observation. |
| Model invocation | model/inference mount call | Local, BYOK, provider, TEE, DePIN, or cTEE route. | ModelInvocationReceipt + usage + redaction/custody refs. |
| Private workspace action | cTEE action path | Protected state must not enter provider-rooted plaintext. | CustodyProof/PrivateInferenceReceipt/DeclassificationReceipt as applicable. |
| External connector/API action | AIIP/capability exit or daemon-native connector | External effect, credential, payment, or message boundary. | Authority receipt + connector receipt + policy refs. |
| Worker/service package step | Rust/WASM service module, workload job, or AIIP invocation | Reusable worker/service outcome step. | ModuleInvocationReceipt + delivery/evidence refs. |
| Verifier/auditor step | verifier module | Risk, low confidence, external effects, service contracts. | VerificationReceipt + claim status update. |

### Transitional dispatch rule

Every existing daemon tool should first be expressible as a `StepModuleInvocation`,
even when it still executes in JS.

That means migration does not require a flag day, but it also does not require
backwards compatibility for legacy code paths. The project is alpha; clarity,
canonical ownership, and deletion of obsolete shims are preferred over preserving
old route behavior.

```text
Phase 1:
  JS tool step emits StepModuleInvocation + StepModuleResult wrappers.

Phase 2:
  selected step routes to Rust workload backend in shadow mode.

Phase 3:
  selected step routes to Rust workload backend in gated mode.

Phase 4:
  selected step routes to Rust workload backend in live mode.

Phase 5:
  obsolete JS execution path is deleted or demoted to a non-authoritative
  client adapter.
```

## Part IV: Truth, Receipts, and Replay

This part explains how a backend result becomes admitted operational truth.
Execution can be migrated backend by backend, but meaningful transitions still
need one receipt-bound path into Agentgres, artifact refs, state roots, and
workflow projections.

### One admitted truth path

All meaningful transitions converge here:

```text
StepModuleResult
  -> receipt refs
  -> artifact/payload refs
  -> Agentgres operation proposal
  -> state-root/head validation
  -> Agentgres operation commit or rejection
  -> projection update
```

Daemon-local JSON state may continue during migration, but it must be treated as:

```text
projection
fixture
cache
compatibility export
```

not as final live truth for serious runs.

### Receipt classes to unify

| Receipt class | Current source | Target binding |
| --- | --- | --- |
| ToolUseReceipt | JS daemon tool dispatch, Rust agentic runtime, workload receipts | `StepModuleInvocation` + `workflow_node_id` + `state_root_before/after`. |
| ModelInvocationReceipt | model mounting store and workload inference path | common model mount invocation envelope. |
| AgentgresOperationReceipt | Agentgres operation append/commit | emitted after operation accepted or rejected. |
| ArtifactRecordedReceipt | daemon artifact store and Agentgres artifact plane | created whenever payload bytes cross artifact-ref boundary. |
| VerificationReceipt | tests/lint/verifier modules | claim refs + evidence refs + result status. |
| OutputOwnershipReceipt | final model/worker ownership pass | proves final output ingested relevant evidence, receipts, and uncertainty. |
| CustodyProof / cTEE receipts | Private Workspace path | proves no-plaintext-custody route and declassification/capability exits. |

### State-root rules

For each module invocation:

```text
state_root_before
  required for Rust/WASM workload-backed consequential modules

state_root_after
  required when the invocation mutates canonical state

projection_watermark
  required when the IDE reads or replays state

expected_heads
  required when Agentgres operation admission depends on object heads
```

If a daemon-native JS tool has no state-root backend yet, it must still produce
a stable `input_hash`, `output_hash`, receipt ref, and projection record so it
can be shadowed by a Rust/WASM module later.

## Part V: Workflow Compositor as Control Plane

This part keeps Hypervisor IDE out of the "pretty canvas only" trap. The
compositor should operate as the visual control plane over the same module graph
the daemon routes, the Rust/WASM backend executes, and Agentgres admits.

### Compositor purpose

Hypervisor IDE's workflow compositor should not be only a canvas. It should be
the operator's visual control plane over the same module graph the daemon and
kernel execute.

It should show:

- workflow graph and node status;
- module kind and backend;
- authority scopes and approval gates;
- context chamber and topology boundaries;
- artifact refs and payload refs;
- receipt timeline and replay availability;
- state-root/projection-watermark status;
- cTEE custody state and leakage profile;
- verifier status and unresolved uncertainty;
- package/module candidate status;
- upgrade proposals and eval gates.

### Governable module graph

The compositor should model workflows as:

```yaml
WorkflowModuleGraph:
  workflow_graph_id: workflow:...
  profile: default-harness-profile
  nodes:
    - workflow_node_id: node:...
      module_ref: module://...
      component_kind: planner | tool | model | verifier | policy | output | receipt
      backend_preference:
        - rust_wasm
        - daemon_js
      authority_scopes_required:
        - scope:...
      primitive_capabilities_required:
        - prim:...
      custody_profile: public | redacted | private_workspace_ctee | tee_confidential
      expected_receipts:
        - ToolUseReceipt
        - VerificationReceipt
      execution_mode: projection | shadow | gated | live
  edges:
    - from: node:...
      to: node:...
      type: depends_on | verifies | informs | blocks | settles | emits
```

### Trace-to-module conversion

Successful traces should become candidates, not direct self-modifications:

```text
successful repeated trace
  -> module candidate
  -> manifest candidate
  -> benchmark/eval fixtures
  -> receipt obligations
  -> policy/authority review
  -> shadow execution
  -> gated execution
  -> Agentgres commit
  -> optional package publication
```

### User-facing views

| View | Must display |
| --- | --- |
| Graph view | module nodes, backend, status, dependencies, blockers. |
| Authority view | `scope:*`, `prim:*`, approvals, grants, step-up requirements, revocation. |
| Receipts view | ordered receipt timeline, evidence refs, state roots, verification status. |
| Context topology view | chambers, boundaries, compaction state, retrieval refs, private/public split. |
| cTEE view | plaintext-free runtime mount, custody type, leakage profile, declassification gates. |
| Replay view | deterministic replay sources, artifact refs, state roots, projection watermarks. |
| Package view | worker/service/module candidate, benchmark status, marketplace readiness. |

## Part VI: Governed Meta-Improvement

This part defines how the harness becomes self-improving without becoming
self-mutating. Runtime learning produces candidates and proposals; authority,
evaluation, receipts, and Agentgres admission decide what becomes live.

### Principle

The Default Harness Profile and agent runtime may improve themselves, but only
through proposal-mediated governance.

Forbidden:

```text
agent edits live harness policy or module and starts using it directly
```

Required:

```text
agent proposes improvement
  -> daemon records proposal
  -> simulation/eval/verifier gates run
  -> wallet.network/governance approves or denies
  -> Agentgres commits accepted operation
  -> shadow/gated/live rollout follows policy
```

### Improvement inputs

The runtime can mine:

- run traces;
- failed-run analyses;
- blocker patterns;
- approval friction;
- context topology drift;
- compaction omissions;
- verifier failures;
- tool error distributions;
- model route outcomes;
- package reuse patterns;
- cost/latency/resource usage;
- user corrections;
- successful repeated workflows;
- cTEE leakage/custody reports;
- service delivery acceptance/dispute outcomes.

### Candidate outputs

| Candidate | Examples |
| --- | --- |
| Skill candidate | repeated local troubleshooting sequence, repo-specific workflow, UI automation procedure. |
| Module candidate | verifier module, connector adapter, route selector, receipt writer, output checker. |
| Workflow candidate | PR creation workflow, quant backtest workflow, Discord moderation service flow. |
| Policy candidate | approval rule, cTEE declassification rule, route fallback rule, budget rule. |
| Schema candidate | `StepModuleInvocation` field addition, receipt schema, artifact projection. |
| Prompt candidate | model pass prompt, output ownership prompt, verifier prompt. |
| Route candidate | model mount route, worker package route, service package route. |

### Proposal object

```yaml
RuntimeImprovementProposal:
  proposal_id: proposal://...
  proposed_by: worker:... | runtime:... | user:...
  target_kind:
    skill | service_module | workflow_graph | policy | schema |
    prompt | route | projection | verifier | package_manifest
  target_ref: string
  change_ref: artifact://...
  evidence:
    trace_refs:
      - trace://...
    receipt_refs:
      - receipt://...
    benchmark_refs:
      - benchmark://...
    failure_refs:
      - failure://...
  expected_effects:
    safety: string
    cost: string
    latency: string
    authority: string
    privacy: string
  rollout:
    initial_mode: shadow
    promotion_gate: gated
    live_requires_approval: true
  status:
    drafted | simulated | verified | approved | rejected |
    committed | shadow | gated | live | rolled_back
```

### Required gates

No self-improvement candidate becomes live until:

- schema validation passes;
- deterministic tests or simulation pass;
- verifier agrees the change does not widen authority silently;
- receipt obligations are satisfied;
- cTEE custody impact is known when private workspace data is involved;
- benchmark/eval threshold passes;
- rollback path exists;
- wallet.network/governance approval is recorded if authority, privacy, cost, or external effect changes;
- Agentgres commits the accepted operation.

## Part VII: Migration Program

This part is the implementation migration, not a pre-migration plan. Carrying
out the master guide means completing this program through terminal conformance.

The program keeps the migration staged, testable, and reviewable: inventory
first, ABI second, bridge third, one shadowed tool fourth, then receipts,
compositor, cTEE, packages, self-improvement, Rust core, facade retirement, and
full conformance.

### Current sprint lane

The current lane is Rust substrate migration, not doctrine expansion. The
latest wired conformance tiers pass for the currently migrated surface, but the
terminal condition is still open. Sprint work should therefore prioritize macro
authority cuts that turn current Rust bridge/admission primitives and
fail-closed JS facades into positive Rust daemon-core APIs.

Current sprint objective:

- route each remaining live daemon route family through Rust core ownership for
  authority, StepModuleRouter dispatch, receipt/state-root binding, Agentgres
  admission, projection, cTEE custody, and replay semantics;
- demote surviving JS/TS code to product/API/IDE/SDK adapter behavior only;
- delete or fail-close compatibility shims once the canonical Rust-owned path is
  verified by focused tests and the tiered conformance command;
- avoid micro-slices that only retire one helper, one alias, or one doc marker
  unless that change completes a larger authority-boundary cut;
- update the migration matrix as a compact macro ledger, not as a per-slice
  evidence archive;
- keep `hypervisor-conformance` green while preserving the honest status:
  "passes at current tier surface" until terminal conditions below are true.

This lane should not promote planned HypervisorOS, custody-proof, private
operator, or marketplace lifecycle concepts into implementation claims unless a
slice actually wires the code path, receipts, and conformance guard. Those items
remain important long-term cleanup or product/runtime evolution targets; the
current sprint is the route-family migration and facade retirement needed to
finish the master guide.

### Terminal condition

The master guide has been carried out only when migration ends. Migration ends
when the split brain is resolved.

That means:

- Hypervisor Daemon has an authoritative Rust core for hot-path execution
  semantics, authority gates, StepModuleRouter dispatch, cTEE custody checks,
  receipt/state-root binding, replay, and conformance.
- Rust/WASM workload/kernel backends execute admitted step and module work
  through the shared Step/Module contract.
- Agentgres is the admitted truth path for meaningful transitions.
- Hypervisor IDE/CLI/SDK interact through stable protocol APIs instead of
  depending on legacy JS daemon execution routes.
- Legacy JS authoritative paths, compatibility shims, and split-brain fallback
  routes have been deleted or demoted into non-authoritative clients.
- The full conformance suite passes.

After that point, new work is ordinary product/runtime evolution, not migration.
Any future change that reintroduces duplicate authority, duplicate truth paths,
or permanent fallback execution paths is a regression against this guide.

### Conformance command contract

The migration is not complete until the repo exposes a single conformance entry
point plus narrow tier commands. The exact task runner can be `just`, `make`,
`npm`, or a repo-native equivalent, but the contract should read like this:

```text
hypervisor-conformance
  runs the complete terminal suite

hypervisor-conformance:docs
  checks terminology, source-of-truth maps, implementation matrix, and stale
  live-architecture wording

hypervisor-conformance:abi
  validates StepModuleInvocation / StepModuleResult schema coverage for every
  live route family

hypervisor-conformance:bridge
  proves daemon route -> Rust core -> workload/module execution paths

hypervisor-conformance:receipts
  proves receipt, ArtifactRef/PayloadRef, Agentgres operation, and state-root
  binding

hypervisor-conformance:ctee
  proves private workspace custody, declassification, leakage, and plaintext
  mount failure behavior

hypervisor-conformance:compositor
  proves IDE workflow projections, replay metadata, and route-family status

hypervisor-conformance:negative
  proves forbidden bypasses fail closed
```

Terminal acceptance should cite the exact command names that exist in the repo.
Until those commands exist, Phase 11 is not complete.

### Phase dependency graph

```text
Phase 0 inventory/canon reconciliation
  -> Phase 1 Step/Module ABI
     -> Phase 2 daemon-to-workload bridge
        -> Phase 3 first shadowed daemon tool
           -> Phase 4 receipts/state roots
              -> Phase 5 compositor projection
                 -> Phase 6 cTEE private workspace path
                 -> Phase 7 worker/service package path
                    -> Phase 8 governed meta-improvement
                       -> Phase 9 Rust daemon core extraction
                          -> Phase 10 JS facade retirement
                             -> Phase 11 full conformance
```

The graph is mostly linear because each phase removes ambiguity needed by the
next. Phase 6 and Phase 7 may proceed in parallel after receipt/state-root and
projection semantics are stable, but both must land before governed
meta-improvement can safely promote reusable modules or package candidates.

### Implementation operating discipline

The migration should optimize for future comprehensibility and terminal
ownership, not only immediate feature velocity or local proof wins. Split-brain
architecture often reappears when files become too large, concepts are
scattered, compatibility shims linger, or dirty worktrees make it unclear what
changed in which cut.

Use these rules for every implementation cut:

#### Macro-cut bias

The default unit of work is a macro authority cut. A good cut moves one whole
truth path closer to Rust ownership:

```text
JS fail-closed/protocol facade
  -> Rust daemon-core positive API
  -> Agentgres admission and expected-head/state-root binding
  -> receipt/projection/replay contract
  -> IDE/CLI/SDK protocol surface
  -> delete or demote the JS facade
```

Small cuts are acceptable only when they unlock or finish that larger boundary.
Do not optimize for maximum slice count, isolated alias retirement, or
documentation churn. Prefer one reviewable end-to-end ownership move over many
helper-level retirements.

#### Refactor pressure

Refactor when code becomes monolithic, mixed-owner, or hard to reconstruct after
context compaction.

Signals that a file or module needs splitting:

- one file mixes route handling, authority, execution, receipt writing,
  projection shaping, and tests;
- a file grows large enough that a new implementer cannot identify the owner
  boundary in a few minutes;
- functions carry many unrelated concepts such as workflow UI, Agentgres
  admission, wallet authority, and workload IPC together;
- the same object mapping appears in multiple places;
- a future agent would need to reread a large file after compaction just to
  understand a small local change;
- old JS and new Rust paths coexist without a named transition boundary.

Preferred refactor shape:

```text
route/API adapter
  -> authority/gate module
  -> StepModuleRouter adapter
  -> backend runner
  -> receipt/state-root binder
  -> projection mapper
```

Each piece should have one owner, one reason to change, and a small set of
conformance tests.

#### Clean-cut commits

Each implementation cut should end with:

```text
targeted tests/checks pass
git diff --check passes for touched files
git status is understandable
commit created for the cut
commit pushed after the cut is verified
```

Do not stack unrelated changes in one dirty worktree. A macro cut may touch JS,
Rust, docs, conformance, and protocol clients when those files are all part of
the same authority move. Clean commits are still part of the architecture
because they make rollback, review, and context recovery possible.

Recommended cut shape:

```text
one route-family positive path
or one Rust daemon-core API family
or one projection/readback family
or one runner-family replacement
or one facade family deletion after Rust parity
```

Avoid unrelated mega-cuts. Do not avoid multi-file macro cuts when those files
are required to complete one verified end-to-end seam.

#### Alpha compatibility policy

This codebase is alpha and has no downstream users that require legacy API
stability. Do not preserve compatibility shims once the new canonical path is
verified.

Use shims only as short-lived migration scaffolds:

```text
introduce shim
  -> shadow/gated/live parity proves new path
  -> remove old path
  -> update source-of-truth docs and compact matrix row
  -> commit and push the cut
```

Do not keep:

- legacy route aliases;
- duplicate JS and Rust execution implementations;
- deprecated object names;
- fallback provider paths that bypass the daemon-owned model-mounting path;
- compatibility adapters that can mutate state or emit accepted receipts.

When a route family migrates, the old authoritative path should be deleted or
demoted into a non-authoritative client adapter.

#### Route-family owner map

Every route family should carry a current owner, final owner, and deletion
condition. This prevents "temporary" dual ownership from becoming architecture.

| Route family | Current owner | Final owner | Deletion / demotion condition |
| --- | --- | --- | --- |
| Coding tools and file mutations | JS daemon tool dispatch | Rust daemon core `step_router` + workload/WASM backend | Rust path passes shadow/gated/live parity and receipts/state roots bind. |
| Approvals and gates | JS daemon routes plus local approval state | Rust core `authority` with wallet.network handoff | JS can only render/request approval, not decide or issue grants. |
| Runtime events, replay, trace | JS daemon envelope/projection code | Rust core `projection` + Agentgres projection watermarks | Rust emits canonical projection records consumed by IDE/SDK. |
| Model mounting and route decisions | JS model-mounting store/routes | Rust core `model_mount` with daemon-owned route policy | Rust records model invocation receipts and route/custody refs. |
| Agentgres operations | daemon-local operation-like records plus target canon | Rust core `agentgres_admission` | no JS path can append accepted operations directly. |
| Receipt binding | JS receipts plus Rust/workload receipts | Rust core `receipt_binder` | every meaningful route family emits receipts through one binder. |
| cTEE Private Workspace actions | canon plus partial product path | Rust core `ctee` | plaintext-free mount and declassification failure tests pass. |
| Worker/service package invocation | target canon plus Rust service modules | Rust core `step_router` + workload/WASM/AIIP backend | package invocation has receipts, authority, artifacts, and compositor projection. |
| External capability exits | daemon-native connector/capability paths | Rust core `authority` + AIIP/capability exit adapter | connector cannot bypass wallet.network scopes or receipt binding. |
| Workflow compositor projections | IDE/daemon projection shaping | Rust core projection source consumed by IDE | IDE displays state but does not create accepted truth. |

#### Implementation cut template

Use this template for each macro cut in the migration. The `ImplementationSlice`
key is retained for older tooling, but the unit is now an authority-boundary cut,
not a helper-level slice.

```yaml
ImplementationSlice:
  objective: one clear authority-boundary outcome
  owner_boundary:
    route_or_surface: ...
    authority_gate: ...
    execution_backend: ...
    truth_path: ...
    projection_path: ...
  touched_files:
    docs: []
    daemon: []
    rust_core: []
    ide: []
    tests: []
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands: []
    replay_or_shadow_comparison: required | not_applicable
  cleanup:
    legacy_paths_removed: true | false
    compatibility_shims_remaining:
      - shim name plus removal condition
    js_facade_demoted_or_deleted: true | false
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

Matrix update rule:

```text
update route-family row
update macro authority cut ledger
update remaining terminal blockers only if the blocker changed
do not add per-slice evidence sections
```

### Phase 0: Inventory and canon reconciliation

Objective:
Create an exact live/substrate/canon inventory so future work does not argue
from vibes.

Implementation work:

- Build a source-of-truth table for daemon JS tools, Rust agentic runtime kernel
  primitives, workload IPC endpoints, WASM service entrypoints, model-mounting
  routes, IDE workflow compositor projections, Agentgres refs, and cTEE docs.
- Add a "live vs target" annotation to any docs that imply Rust/WASM already
  executes all Hypervisor steps.
- Confirm naming uses Hypervisor and Default Harness Profile.

Likely files/modules:

- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/implementation-matrix.md`
- `docs/architecture/components/daemon-runtime/default-harness-profile.md`
- `docs/architecture/foundations/domain-kernels.md`
- `packages/runtime-daemon/src/coding-tools.mjs`
- `crates/services/src/agentic/runtime/kernel/*`
- `crates/vm/wasm/src/*`
- `crates/validator/src/standard/workload/*`

Conformance checks:

- no stale "Default Harness Runtime" live wording;
- no "Rust/WASM runtime beside daemon" wording;
- no "Autopilot" product references except historical/deprecated contexts if any remain.

Tests/proofs:

- `git diff --check -- docs/architecture`
- `rg -n "Default Harness Runtime|Autopilot" docs/architecture`

Risks:

- over-editing canon before implementation catches up.

Acceptance criteria:

- every major runtime responsibility has one owner and one current implementation anchor.

### Phase 1: Step/Module ABI definition

Objective:
Define the shared ABI before migrating execution.

Implementation work:

- Add `StepModuleInvocation` and `StepModuleResult` schemas.
- Map existing JS runtime events into ABI wrappers.
- Map Rust `ToolInvocationEnvelope`, `ModelInvocationEnvelope`,
  `WorkflowInvocationEnvelope`, and `GraphInvocationEnvelope` into the ABI.
- Define how receipt refs, artifact refs, state roots, authority refs, context
  chamber refs, and workflow projection metadata bind.

Likely files/modules:

- `crates/services/src/agentic/runtime/kernel/invocation.rs`
- `crates/services/src/agentic/runtime/harness.rs`
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`
- `packages/runtime-daemon/src/runtime-tool-surface.mjs`
- `packages/agent-ide/src/runtime/harness-workflow/*`
- `docs/architecture/_meta/implementation-matrix.md`

Conformance checks:

- every existing daemon tool can be represented as a `StepModuleInvocation`;
- every invocation returns enough metadata for IDE projection.

Tests/proofs:

- Rust unit tests for ABI validation.
- JS tests that each coding tool emits an ABI wrapper in dry-run/projection mode.

Risks:

- ABI becomes too broad or too abstract.

Acceptance criteria:

- a no-op/projection run can produce a full `StepModuleInvocation` and
  `StepModuleResult` for every current JS tool without changing behavior.

### Phase 2: Runtime-daemon bridge to Rust workload client

Objective:
Let the Node daemon call the Rust workload/control plane without losing daemon
authority ownership.

Implementation work:

- Add `StepModuleRunner` interface in `packages/runtime-daemon`.
- Add `RustWorkloadStepModuleRunner` using a command bridge first, then direct
  gRPC/IPC when bindings are ready.
- Treat the command bridge as a migration transport only. It may prove the Rust
  workload/client path, but it is not the final daemon-core shape and must not
  accumulate independent authority, accepted-truth mutation, or compatibility
  wrappers.
- Bind runner outputs into existing runtime event envelope and thread/run replay.
- Add configuration:

```text
IOI_WORKLOAD_GRPC_ADDR=...
IOI_SHMEM_ID=...
```

`IOI_STEP_MODULE_BACKEND` is retired. Any explicit backend selection fails
closed in the runtime-daemon StepModule runner, including the formerly accepted
`rust_workload_live` value. Historical shadow/gated bridge fixtures remain
history only; the current daemon edge is live Rust workload execution by
construction, or no execution.

Likely files/modules:

- `packages/runtime-daemon/src/runtime-profile.mjs` as the runtime-profile helper; the bridge-named `runtime-api-bridge.mjs` module is deleted and must not return as compatibility scaffolding
- `packages/runtime-daemon/src/runtime-route-handlers.mjs`
- `packages/runtime-daemon/src/coding-tools.mjs`
- `crates/client/src/workload_client/mod.rs`
- `crates/ipc/proto/control/v1/control.proto`
- `crates/validator/src/standard/workload/ipc/grpc_control.rs`

Conformance checks:

- StepModule execution defaults to the Rust workload live path and explicit
  `daemon_js` selection fails closed;
- bridge cannot bypass approval gates;
- bridge cannot create Agentgres operations without daemon admission path.

Tests/proofs:

- JS unit test for runner selection and fail-closed behavior.
- Rust workload-control e2e remains green.
- Integration smoke test for daemon -> bridge -> workload mock -> event envelope.

Risks:

- transport mismatch, auth mismatch, duplicate receipt emission.

Acceptance criteria:

- one dry-run daemon step can route to workload mock in shadow mode and produce
  the same workflow projection as daemon-native execution.

### Phase 3: First daemon tool routed through Rust/WASM module backend

Objective:
Move one low-risk, deterministic step through the Rust/WASM path.

Recommended first candidates:

1. `workspace.status` as read-only projection.
2. `lsp.diagnostics` as evidence-producing verifier.
3. `test.run` as workload job if command sandboxing is ready.

Implementation work:

- Build a WASM service module or Rust workload job for the selected tool.
- Route JS daemon invocation through `StepModuleRunner` in shadow mode.
- Compare daemon-native result to Rust/WASM result.
- Promote to gated/live only after divergence is understood.

Likely files/modules:

- `packages/runtime-daemon/src/coding-tools.mjs`
- `crates/vm/wasm/src/lib.rs`
- `crates/vm/wasm/src/wasm_service.rs`
- `crates/services/src/agentic/runtime/execution/*`
- `crates/cli/tests/*agentic*`

Conformance checks:

- identical normalized observation shape;
- receipt includes module id/version and workflow node id;
- no authority widening.

Tests/proofs:

- shadow comparison test.
- workflow compositor snapshot/projection test.
- Rust unit/e2e test for service module execution.

Risks:

- first module chosen is too mutating or has too many OS-specific assumptions.

Acceptance criteria:

- selected tool can run through Rust/WASM backend in shadow mode with stable
  event, receipt, and projection output.

### Phase 4: Receipt and state-root unification

Objective:
Make daemon-native and workload-backed steps converge into Agentgres operation
and state-root semantics.

Implementation work:

- Add `state_root_before`, `state_root_after`, `expected_heads`, and
  `projection_watermark` to step/module result records where applicable.
- Bind JS receipt refs to Agentgres operation refs.
- Define when daemon-local state is cache/projection versus admitted truth.

Likely files/modules:

- `packages/runtime-daemon/src/threads/thread-replay.mjs`
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`
- `packages/runtime-daemon/src/model-mounting/store.mjs`
- `docs/architecture/components/agentgres/*`
- `crates/validator/src/standard/workload/ipc/grpc_blockchain.rs`
- `crates/services/src/agentic/runtime/kernel/settlement.rs`

Conformance checks:

- no meaningful transition lacks a receipt;
- no artifact payload is meaningful without an ArtifactRef/PayloadRef;
- no restore/import mutates local files without Agentgres operation path.

Tests/proofs:

- replay test reconstructs step result from operation + receipts + artifact refs.
- state-root mismatch test fails closed.

Risks:

- premature replacement of local daemon projections.

Acceptance criteria:

- one workload-backed step and one daemon-native step produce comparable
  Agentgres-admissible operation envelopes.

### Phase 5: Workflow compositor projection upgrade

Objective:
Make Hypervisor IDE display the same substrate the daemon executes.

Implementation work:

- Add module backend, execution mode, state-root, receipt, artifact, custody,
  and authority metadata to workflow node projections.
- Add graph controls for projection/shadow/gated/live execution modes.
- Add cTEE/custody badges and declassification gates.
- Add receipt timeline and replay links per node.

Likely files/modules:

- `packages/agent-ide/src/runtime/harness-workflow/*`
- `packages/agent-ide/src/runtime/workflow-composer-model.ts`
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`
- `packages/runtime-daemon/src/runtime-route-handlers.mjs`

Conformance checks:

- compositor never displays a mutating node as safe when approval is missing;
- compositor distinguishes projection/shadow/gated/live states;
- cTEE nodes reveal custody posture without revealing protected content.

Tests/proofs:

- TS unit tests for workflow graph projections.
- UI tests or snapshot tests for authority/custody/receipt badges.

Risks:

- compositor becomes decorative instead of authoritative.

Acceptance criteria:

- a user can inspect why each workflow node is allowed, blocked, shadowed,
  verified, or live.

### Phase 6: cTEE Private Workspace module path

Objective:
Route private workspace actions through the shared ABI while preserving
no-plaintext-custody invariants.

Implementation work:

- Add `privacy_profile`, `plaintext_policy`, `custody_proof_ref`,
  `leakage_profile_ref`, and declassification refs to the ABI.
- Add Private Workspace module runner categories:

```text
public_trunk_job
redacted_projection_job
candidate_lattice_generation
private_head_selection
declassification_gate
capability_exit
```

- Bind wallet.network authority view to declassification and capability exits.
- Emit custody receipts.

Likely files/modules:

- `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`
- `packages/runtime-daemon/src/model-mounting/*`
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`
- `crates/ipc/src/data.rs`
- `crates/services/src/agentic/leakage.rs`
- `crates/services/src/agentic/pii_*`

Conformance checks:

- no protected workspace plaintext enters provider-rooted node context by default;
- external actions require capability exit and authority receipt;
- model API boundary is explicit when third-party foundation models are used.

Tests/proofs:

- canary private file/name leakage tests.
- custody proof fixture tests.
- declassification denial/approval tests.

Risks:

- users mistake cTEE for hardware confidential computing.

Acceptance criteria:

- a Private Workspace run can execute public/generic work on a rented node while
  private head/declassification remains in guardian/wallet/local authority path.

### Phase 7: Service package and worker package invocation path

Objective:
Make aiagent.xyz workers and sas.xyz service outcomes run through the same
step/module ABI.

Implementation work:

- Map WorkerPackage and ServicePackage manifests to module graph nodes.
- Route package steps through daemon gates and Rust/WASM/workload/AIIP backends.
- Record delivery/evidence/verification receipts.
- Keep marketplace listing/contracting separate from authority grants.

Likely files/modules:

- `docs/architecture/domains/aiagent-xyz/*`
- `docs/architecture/domains/sas-xyz/*`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `packages/runtime-daemon/src/runtime-mcp-*`
- `crates/services/src/agentic/runtime/kernel/marketplace.rs`

Conformance checks:

- aiagent.xyz packages capability but does not grant authority;
- sas.xyz packages outcomes but does not bypass daemon/wallet gates;
- package execution emits module invocation receipts.

Tests/proofs:

- package manifest validation tests.
- service delivery receipt tests.
- authority-denial tests.

Risks:

- marketplace path becomes a bespoke interop protocol.

Acceptance criteria:

- worker and service package invocations are graph/module invocations, not
  special-case product calls.

### Phase 8: Meta-improvement proposal path

Objective:
Allow the runtime to improve skills, modules, workflows, routes, schemas, and
policies safely.

Implementation work:

- Add runtime improvement proposal objects.
- Add trace-mining candidate generation.
- Add simulation/eval/verifier gates.
- Add approval and Agentgres commit path.
- Add IDE proposal review and rollback view.

Likely files/modules:

- `crates/services/src/agentic/runtime/kernel/plan.rs`
- `crates/services/src/agentic/evolution.rs`
- `packages/runtime-daemon/src/skill-hook-*`
- `packages/runtime-daemon/src/runtime-skill-hook-surface.mjs`
- `packages/agent-ide/src/runtime/harness-workflow/*`

Conformance checks:

- no direct self-mutation;
- authority changes require approval;
- rollback refs exist.

Tests/proofs:

- failed-run candidate creation test.
- proposal gate test.
- rollback/revert test.

Risks:

- "self-improvement" becomes ungoverned prompt editing.

Acceptance criteria:

- a successful trace can become a module/workflow candidate, pass shadow/eval
  gates, and be committed only through Agentgres plus approval.

### Phase 9: Rust daemon core extraction

Objective:
Move the proven hot-path daemon responsibilities into a Rust daemon core while
preserving the product/API facade and avoiding a disruptive rewrite.

Implementation work:

- Create a Rust `hypervisor-daemon-core` crate or equivalent module boundary
  inside the existing Rust workspace.
- Move `StepModuleRouter` dispatch, workload-client calls, policy/authority
  gate evaluation, receipt binding, Agentgres operation admission, cTEE custody
  checks, resource leases, cancellation, replay validation, and state-root checks
  into Rust.
- Keep current JS daemon routes only as short-lived transition adapters that
  call the Rust core through native bindings, IPC, or command bridge during
  transition.
- Retire or collapse the migration command bridge once a route family has a
  stable Rust daemon-core API/protocol. A remaining process boundary is allowed
  only as a narrow transport owned by the Rust daemon core, not as a second
  runtime surface.
- Migrate one route family at a time:

```text
tools/invoke
  -> approvals
  -> run events/replay/trace
  -> model mounting route decisions
  -> Agentgres operation admission
  -> cTEE custody/declassification paths
```

- Keep IDE and SDK product behavior coherent while moving the implementation
  below them; do not preserve obsolete response shapes for legacy callers.

Likely files/modules:

- new Rust core boundary under `crates/*` once named;
- `packages/runtime-daemon/src/runtime-route-handlers.mjs`;
- `packages/runtime-daemon/src/coding-tools.mjs`;
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`;
- `packages/runtime-daemon/src/model-mounting/*`;
- `crates/client/src/workload_client/mod.rs`;
- `crates/ipc/*`;
- `crates/services/src/agentic/runtime/kernel/*`;
- `crates/services/src/agentic/runtime/harness.rs`;
- `crates/vm/wasm/src/*`;
- `crates/validator/src/standard/workload/*`.

Conformance checks:

- JS facade cannot bypass Rust core for migrated hot-path responsibilities;
- migrated Rust core behavior preserves existing IDE/API output shapes;
- authority and receipt behavior remains stable across the migration;
- no duplicate sources of truth are introduced.

Tests/proofs:

- route parity tests: JS facade response equals old behavior while core handles
  execution for the current product surface;
- Rust unit tests for router/gate/receipt/state-root/custody primitives;
- cross-boundary integration tests for daemon route -> Rust core -> workload;
- rollback test that can switch a route family back to JS fallback during
  migration without losing receipts.

Risks:

- premature port recreates unstable JS surface area instead of extracting proven
  core behavior;
- native binding complexity obscures the authority boundary;
- temporary dual paths diverge.

Acceptance criteria:

- at least one complete run path executes through the Rust daemon core while
  the IDE/API facade remains stable;
- hot-path execution and canonical admission logic live in Rust for that path;
- JS is demonstrably acting as facade/adaptor, not as execution substrate;
- the `ioi-step-module-bridge` command path is either retired for that route
  family or documented as a temporary transport to the Rust daemon core with no
  independent authority or compatibility-shim behavior.

### Phase 10: Authoritative JS facade retirement

Objective:
Remove JS/TS from authoritative daemon runtime paths after Rust core route-family
parity is proven.

Implementation work:

- For each migrated route family, replace JS implementation ownership with a
  stable Rust core API.
- Keep TypeScript clients only as IDE/SDK/product adapters.
- Delete or fail-close deprecated JS execution paths once the Rust core route is
  live.
- Add transition shims only when they cannot mutate state or bypass Rust
  authority/admission logic, and delete them in the same or immediately
  following verified slice.
- Update docs and source-of-truth maps so `packages/runtime-daemon` no longer
  reads as the canonical daemon implementation for migrated responsibilities.

Likely files/modules:

- `packages/runtime-daemon/src/*` route families that have Rust-core parity;
- new Rust daemon core API modules;
- `packages/agent-ide/src/*` client adapters;
- `packages/agent-sdk/*` protocol bindings;
- `docs/architecture/_meta/source-of-truth-map.md`;
- `docs/architecture/_meta/implementation-matrix.md`.

Conformance checks:

- no migrated authoritative path calls JS execution logic;
- JS adapters cannot append accepted operations directly;
- JS adapters cannot issue authority grants, receipts, or cTEE custody proofs;
- all mutation paths pass through the Rust core and Agentgres admission path.

Tests/proofs:

- route-family deletion tests proving old JS execution path is inaccessible;
- API/product-shape tests for IDE/SDK clients;
- authority-bypass regression tests;
- state-root/receipt parity tests before and after facade retirement.

Risks:

- deleting facade paths before IDE/SDK clients are ready;
- retaining "temporary" JS fallbacks beyond their verified migration slice;
- product regressions caused by response-shape drift.

Acceptance criteria:

- for each migrated route family, JS/TS is only a non-authoritative client or UI
  adapter;
- the Rust daemon core is the only authoritative implementation for execution,
  authority, receipt, state-root, Agentgres admission, and cTEE custody decisions
  on that route family.

### Phase 11: Full conformance suite

Objective:
Prove the unified substrate end to end.

Implementation work:

- Create conformance tests for ABI coverage, authority gates, receipts, replay,
  state roots, cTEE custody, workflow projections, package invocation, and
  improvement proposals.
- Add a reference demo:

```text
Hypervisor IDE workflow
  -> daemon ActionProposal
  -> wallet.network / daemon GateResult
  -> Rust/WASM module invocation
  -> workload receipt
  -> Agentgres operation
  -> workflow compositor replay
```

Conformance checks:

- no direct mutation without gate;
- no meaningful transition without receipt;
- no storage-backend authority;
- no L1 settlement unless trigger applies;
- no cTEE plaintext custody violation.

Tests/proofs:

- JS unit tests.
- Rust unit tests.
- Rust e2e workload tests.
- cross-boundary daemon-to-workload integration test.
- replay/state-root conformance test.
- cTEE leakage canary test.
- negative conformance tests:
  - direct JS authoritative mutation fails;
  - direct accepted receipt append outside the Rust core fails;
  - Agentgres operation append without expected heads/state-root binding fails;
  - storage backend write without Agentgres ArtifactRef/PayloadRef fails;
  - cTEE private workspace plaintext mount on an untrusted node fails;
  - external capability exit without wallet.network authority fails;
  - L1 settlement attempt without trigger fails;
  - workflow compositor attempt to create accepted truth directly fails.

Risks:

- broad suite becomes flaky without stable fixtures.

Acceptance criteria:

- implementer can run one command or small command set and see full substrate
  conformance status.
- implementation migration is complete: no authoritative JS execution path,
  duplicate truth path, split-brain fallback, or unverified compatibility shim
  remains.
- future work proceeds as ordinary product/runtime evolution against the unified
  substrate.

## Part VIII: Conformance Failures and Anti-Patterns

This part names the mistakes that would recreate the split brain or weaken the
canon boundaries. Treat these as failed conformance checks, not stylistic
preferences.

Reject these explicitly:

1. Treating the Rust/WASM kernel as a separate runtime beside the daemon.
2. Treating the Node daemon as the final execution substrate forever.
3. Bypassing Agentgres for meaningful transitions.
4. Bypassing wallet.network authority gates, approvals, leases, secrets, or
   declassification control.
5. Treating the workflow compositor as only a UI canvas.
6. Allowing agents to self-modify directly.
7. Treating IOI L1 as default settlement for every step.
8. Treating cTEE as ordinary encryption-at-rest.
9. Treating storage backends as authority layers.
10. Treating marketplace listing as capability authorization.
11. Treating a model mount as proof that private workspace plaintext is safe on
    rented compute.
12. Treating direct JS daemon tools and Rust/WASM modules as unrelated systems.
13. Letting runtime files become monolithic enough that ownership boundaries are
    no longer obvious.
14. Accumulating many unrelated migration changes in a dirty worktree instead of
    committing and pushing verified slices.
15. Keeping legacy compatibility shims after the canonical path is verified.
16. Preserving old API behavior at the cost of source-of-truth clarity while the
    project is still alpha.
17. Hiding split-brain behavior behind fallback paths instead of deleting,
    demoting, or clearly naming them.
18. Treating this master guide as a planning artifact that must be followed by a
    separate implementation migration.

## Part IX: First Concrete Win

This part defines the smallest valuable implementation milestone. It should be
possible to prove the migration shape with one current daemon tool before moving
large route families or product surfaces.

The first visible win should not be a massive rewrite. It should be:

```text
One current daemon tool
  represented by StepModuleInvocation
  shadow-routed to the Rust workload/kernel backend
  compared against the daemon-native result
  recorded with receipts and Agentgres refs
  displayed in the workflow compositor as the same node
```

Once that works, the system has the right migration shape.

Each implementation slice should then be committed and pushed before the next
slice begins. A clean worktree is a conformance aid: it keeps review, rollback,
and context recovery tractable as the daemon, Rust core, workflow compositor,
Agentgres, wallet.network, and cTEE paths converge.

Current lane note: after the public runtime projection family direct API cut,
public runtime account, runtime-node, tool catalog, skill/hook registry,
repository workflow, agent, thread, run, agent-run lifecycle, run wait, run conversation,
thread usage, thread turns, thread turn detail, thread events, run usage, run
events, run replay, run trace/inspect, run computer-use trace/trajectory, run
scorecard, run artifact, top-level usage, authority-evidence, public memory
list/policy/path/status/validation, public/thread-scoped
conversation-artifact route-facing projections, and public subagent
list/get/result projections are no
longer JS-authored public truth. Runtime account/node/tool catalog projections
now call typed `daemonCoreRuntimeProjectionApi.projectRuntimeToolCatalog`,
skill/hook registry projections now call typed
`daemonCoreRuntimeProjectionApi.projectSkillHookRegistry`, repository workflow
projections now call typed
`daemonCoreRuntimeProjectionApi.projectRepositoryWorkflow`, and runtime
lifecycle projections now call typed
`daemonCoreRuntimeProjectionApi.projectRuntimeLifecycle`; all four are backed by
Rust `RuntimeKernelService` projection methods and their old command operations,
dispatch arms, response wrappers, and JS generic `operation` envelopes are
retired. The mounted thread-memory surface
now calls Rust `project_runtime_memory_projection` for public memory
list/policy/path/status/validation before JS `AgentMemoryStore` readback;
conversation-artifact list/get/revision routes call Rust
`project_runtime_conversation_artifact_projection` through the mounted artifact
surface with runtime `state_dir` and reject JS artifact candidate transport,
while artifact create/action/export/promote call Rust
`plan_runtime_conversation_artifact_control` and Rust Agentgres artifact-state
commit before route truth returns; subagent list/get/result routes call Rust
`project_runtime_subagent_projection` through the mounted subagent surface
before JS subagent/run map readback, while subagent wait control uses Rust
`plan_runtime_subagent_control`, Rust runtime-event Agentgres admission, Rust
subagent record state-update planning, and Agentgres-backed `writeSubagent`;
subagent input/resume use the same Rust control/state path plus Rust-owned
child-agent run creation, subagent assign/cancel use the same Rust control/state
path, cancel composes with Rust run-cancel state planning, and cancellation
propagation uses Rust read projection plus propagated-cancel/run-cancel/state
planning before Agentgres-backed subagent persistence; direct subagent
control-event append uses Rust control planning plus Rust runtime-event
Agentgres admission without JS mutation; public workflow-edit proposal/apply
controls call Rust `plan_runtime_workflow_edit_control` and admit only
Rust-authored `workflow.edit_proposed`/`workflow.edit.apply` events through
Rust runtime-event Agentgres admission without JS event, approval, workflow JSON,
or legacy replay authorship; diagnostics repair decision execution and direct
decision-event append call Rust `plan_runtime_diagnostics_repair_control` and
admit only Rust-authored diagnostics repair events through Rust runtime-event
Agentgres admission without JS event append, run-state mutation, or repair-truth
persistence, and diagnostics repair decision resolution calls Rust
`project_runtime_diagnostics_repair_projection` over runtime `state_dir`
Agentgres event replay before accepted repair truth can return without JS
projection readback or decision-candidate transport; diagnostics operator
override execution calls Rust `plan_diagnostics_operator_override_state_update`,
sends raw operator request, decision, repair-policy context, and canonical
wallet authority refs instead of JS approval verdicts, lets Rust derive the
override approval state, requires wallet.network grant and authority receipt
refs for approval-required overrides, rejects retired verdict/authority
transport, and commits only the Rust-planned operator-control run projection
through Rust Agentgres run-state admission without JS run-map mutation; direct
operator-override event append also calls Rust diagnostics repair control
planning, applies the same wallet authority gate, and admits only the
Rust-authored operator-override event through Rust runtime-event admission;
diagnostics repair retry-turn creation composes with the direct Rust-backed
run-create lifecycle API and admits only a Rust-authored retry event through Rust
diagnostics repair event planning/runtime-event admission, while direct
retry-event append uses that same Rust-owned admission path; public agent
create, top-level thread create, agent status/delete, and agent-scoped run
create routes call direct Rust-backed lifecycle APIs; public
runtime account/node/tool catalog routes call the mounted tool surface directly;
public repository workflow routes call the mounted repository surface directly;
public skill and hook catalog routes call the mounted skill-hook registry
surface directly; public model catalog and model-capability routes call the
mounted model-mount read-projection surface directly;
model-mount `server_status` read projection now sends empty request state plus
request-level `base_url` into Rust, and the deleted JS
`serverStatusProjectionInput()` helper can no longer materialize public server
truth from volatile server-control state;
model-mount tokenizer and route-control Rust-core-required planner records now
live in dedicated Rust `model_mount/required/{tokenizer,route_control}.rs`
owner modules behind the facade-only `model_mount/required.rs`, while
backend-lifecycle, server-control, and runtime-engine positive control planners
live in Rust `model_mount/{backend_lifecycle,server_control,runtime_engine}.rs`
behind the stable `ModelMountCore` facade, and the Rust tests now live beside
those child owners instead of accumulating in the broad model-mount kernel file;
model-mount schema constants, `ModelMountError`, receipt-ref validation,
non-empty/string helpers, evidence-ref de-duplication, and SHA-256 helper logic
now live in the dedicated Rust `model_mount/common.rs` module, giving the split
model-mount owner modules one shared Rust foundation rather than re-growing the
broad facade file;
model-mount route-decision and invocation-admission request/record types,
validation, cTEE custody/plaintext checks, receipt binding checks, and admission
hashing now live in the dedicated Rust `model_mount/admission.rs` module behind
`ModelMountCore`, making the model-route and invocation admission gate a
distinct Rust core boundary rather than broad model-mount helper code, and the
admission Rust tests now live beside those gates instead of accumulating in the
broad model-mount kernel file;
model-mount backend-process plan request/result types, validation, public/spawn
argument shaping, readiness status, evidence refs, and plan hashing now live in
the dedicated Rust `model_mount/backend_process.rs` module behind
`ModelMountCore::plan_backend_process`, and the backend-process Rust
tests/fixtures now live beside that planner instead of in the broad parent
facade, keeping backend-process ownership directional toward Rust core
process/lifecycle APIs rather than a long-term Node bridge shape;
model-mount accepted-receipt head/transition request/result types, validation,
state-root derivation, operation/head refs, transition hashing, and tamper
validation now live in the dedicated Rust `model_mount/accepted_receipt.rs`
module behind `ModelMountCore`, and the accepted-receipt Rust tests/fixtures
now live beside that implementation instead of in the broad parent facade,
making receipt/state-root binding a distinct Rust core boundary rather than
broad model-mount helper code;
model-mount provider lifecycle, provider inventory, and model-instance
lifecycle request/result types, validation, backend/driver classification,
evidence refs, and transition hashes now live behind the Rust
`model_mount/lifecycle.rs` facade, with provider lifecycle owned by
`model_mount/lifecycle/provider.rs`, provider inventory owned by
`model_mount/lifecycle/inventory.rs`, and model-instance lifecycle owned by
`model_mount/lifecycle/instance.rs`; `ModelMountCore` still forwards through
the facade, but each lifecycle family now carries its own module-local Rust
proof so the next direct daemon-core API cut can retire JS edge translation
without treating the broad lifecycle facade as the long-term owner;
model-mount provider execution admission now lives in the Rust
`model_mount/provider_execution/admission.rs` boundary behind the
`model_mount/provider_execution.rs` facade and `ModelMountCore`, while
fixture/native-local provider invocation execution lives in
`model_mount/provider_execution/invocation.rs` and native-local stream
invocation chunk planning lives in
`model_mount/provider_execution/stream.rs`; provider-result admission now lives
in the dedicated Rust
`model_mount/provider_result.rs` module behind `ModelMountCore`, making
provider execution and provider-result binding separate Rust core boundaries
for the next direct daemon-core API cuts, and the provider execution,
invocation, stream, and provider-result Rust tests now live beside their owning
modules instead of accumulating in the broad model-mount kernel file;
model-mount read-projection adapter-boundary and workflow-binding projection
authors now live in the dedicated Rust
`model_mount/read_projection/adapter_boundary.rs` module, with module-local
Rust proof that wallet.network, cTEE/vault, OAuth, Agentgres, and workflow node
projection metadata are authored by Rust instead of a JS compatibility helper
or broad dispatcher body;
model-mount server/catalog status and authority-snapshot projection authors now
live in dedicated Rust `model_mount/read_projection/status.rs` and
`model_mount/read_projection/authority.rs` modules, with module-local Rust
proof that server status ignores retired JS status inputs, catalog status
ignores retired catalog-status inputs, and wallet authority summary/readback
metadata is owned outside the broad read-projection dispatcher;
model-mount receipt summary/replay read projections now live in the dedicated
Rust `model_mount/read_projection/receipt.rs` module, route-decision readback
now lives in Rust `model_mount/read_projection/route_decision.rs`, and latest
provider/vault health plus runtime-survey status now live in Rust
`model_mount/read_projection/health.rs`, with module-local Rust proof that
each family is derived from admitted receipt truth instead of JS topology,
provider-health, or runtime-survey materialization;
model-mount aggregate snapshot and projection envelopes now live in the
dedicated Rust `model_mount/read_projection/aggregate.rs` module, with
module-local Rust proof that top-level model_mount readback is assembled from
admitted receipts, projection summary, wallet/vault refs, adapter-boundary
metadata, and Rust-owned status/catalog helpers outside the broad dispatcher;
model-mount runtime-engine read-projection replay now lives in the dedicated
Rust `model_mount/read_projection/runtime.rs` module, with module-local Rust
proof that admitted `runtime-engine-controls` records materialize
engine/profile/preference/default-load/detail truth while caller-supplied JS
runtime-engine maps, profiles, preferences, and default load options cannot
become projection truth;
model-mount topology/product-catalog default read projections now live in the
dedicated Rust `model_mount/read_projection/topology.rs` module, with
module-local Rust proof that caller-supplied JS artifacts, providers,
endpoints, instances, routes, capabilities, downloads, backends,
provider-health rows, runtime catalog rows, and OpenAI-compatible model-list
rows cannot become projection truth;
model-mount public catalog-status readback now returns the Rust-authored
`catalog_status` projection from `model_mount/read_projection/status.rs` with
empty request state plus runtime `state_dir`, replaying admitted
`model-provider-inventory/*.json` Agentgres records into provider status,
storage status, last-search summary, and result rows; model-mount public OAuth
session/state readback now returns Rust-authored redacted rows from
`model_mount/read_projection/oauth.rs` by replaying admitted
`model-catalog-provider-controls/*.json` records with wallet/cTEE custody facts
and filtering legacy JS OAuth truth;
model-mount read-projection shared helpers now live in the dedicated Rust
`model_mount/read_projection/common.rs` module, with module-local Rust proof
that schema/generation defaults, array/object extraction, and receipt-kind
filtering are owned outside the broad dispatcher;
public studio intent-frame routing now calls typed
`daemonCoreRuntimeProjectionApi.projectStudioIntentFrame`, backed by Rust
`studio_intent_frame.rs`, while `studio-intent-frame.mjs` is absent so the
route cannot classify consequential Studio intents through a JS resolver;
public doctor routing now calls typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDoctorReport` and returns the Rust
doctor report, while `runtime-doctor-report.mjs` is absent so the doctor route
cannot recompose readiness through mounted JS tool or skill surfaces;
Rust-live coding-tool invocation can still shape workload results through a
test-injected admission boundary, but the production-default invocation surface
now fails closed before appending an accepted coding-tool result event from JS.
Direct Rust daemon-core result-event admission over Agentgres expected
heads/state roots remains required before the coding-tool lane can be considered
terminal; daemon JS computer-use invocation facades for browser discovery,
control, native browser, visual GUI, and sandboxed hosted execution now fail
closed at entry before JS agent/thread lookup, local execution/projection, or
runtime-event append can author accepted truth; direct Rust daemon-core
computer-use invocation admission over wallet.network authority and Agentgres
expected heads/state roots remains required before that lane can be considered
terminal; daemon JS runtime thread-event append and legacy thread/run event
projection now fail closed before JS event-stream mutation or JSONL persistence
can author accepted replay truth; direct Rust daemon-core thread-event
admission/projection over Agentgres expected heads/state roots remains required
before replay is terminal; runtime agent/subagent persistence now refreshes JS
cache maps only after the Rust Agentgres state commit succeeds, so a rejected
Rust commit cannot leave JS in-memory lifecycle truth behind; model-mount
default seeding no longer writes derived backend records into the JS backend
registry map, and the retired backend seeding facade fails closed before backend
map mutation; public backend list projection now routes through the Rust
model-mount read-projection API with empty JS request state plus runtime
`state_dir` instead of the JS backend registry/readback facade, and Rust replays
admitted `model-backend-lifecycle-controls/*.json` records while filtering
JS-authored lifecycle controls; public backend health/start/stop/log lifecycle controls
now call Rust `plan_model_mount_backend_lifecycle` through the daemon-core
command bridge, receive Rust-authored `model-backend-lifecycle-controls`
records with backend-lifecycle evidence, commit only those records through Rust
Agentgres model_mount record-state admission, and return Rust public responses
before any JS backend registry lookup, derived backend projection, local backend
kind inference, receipt creation, process control, or log read/write can run;
public model-mount server-control start/stop/restart/write, operation
recording, and log append now call typed
`daemonCoreModelMountApi.planModelMountServerControl`, backed by Rust
`RuntimeKernel::plan_model_mount_server_control`, receive Rust-authored
`model-server-controls` records with server-control evidence, commit only
those records through Rust Agentgres model_mount record-state admission, and
return Rust public responses before any JS state write, log write, command
envelope, bridge backend tag, or transport execution can run;
public runtime-engine selection/profile/remove mutations now call typed `daemonCoreModelMountApi.planModelMountRuntimeEngine`, backed by Rust `RuntimeKernelService::plan_model_mount_runtime_engine`,
receive Rust-authored `runtime-engine-controls` records with runtime-engine
evidence, commit only those records through Rust Agentgres model_mount
record-state admission, and return Rust public responses before any JS runtime
preference/profile/projection write or receipt creation can run;
public tokenizer/count/context-fit utility facades now call typed
`daemonCoreModelMountApi.planModelMountTokenizer`, backed by Rust
`RuntimeKernelService::plan_model_mount_tokenizer`, bind the
Rust route-selection record and accepted receipt from `model_mount.route.select`,
commit only Rust-authored tokenizer/context-fit records through Rust Agentgres
model_mount record-state admission, and return committed Rust tokenizer truth
before any JS tokenizer required-record shim, command-envelope bridge,
context-window fallback, tokenization/context-fit receipt synthesis,
route-state mutation, truncation, or response-envelope shaping can run; public `modelTokenizerRecords()` now calls
Rust read-projection kind `model_tokenizer_records` with runtime `state_dir`, and
Rust replays persisted `model-tokenizer-utilities/*.json` Agentgres records while
filtering truth to Rust-authored tokenizer/context-fit records with tokenizer and
Agentgres evidence before any JS tokenizer projection path can return;
public route write/test now request Rust route-control plans through typed
`daemonCoreModelMountApi.planModelMountRouteControl`, backed by Rust
`RuntimeKernelService::plan_model_mount_route_control`, commit only the
Rust-authored route or route-test record through Rust Agentgres model_mount
record-state admission, and return committed Rust route-control truth before
any JS route-record authoring, route-control receipt synthesis, command-envelope
fallback, or duplicate route-state mutation can run; mounted route-selection and
explicit-model endpoint resolution now also request the same typed Rust
route-control plans, commit only Rust-authored
route-selection or endpoint-resolution records through Rust Agentgres
model_mount record-state admission, and return Rust-authored selection truth
before JS route map mutation, endpoint mounting, JS policy evaluation,
candidate scoring, JS-created route-control receipts, or duplicate
route-selection truth can run; runtime explicit/run-override model-route
selection now consumes that same Rust-authored route selection and accepted
receipt truth as a protocol client, without JS fallback route receipt minting;
model-mount read projection planning has moved out of the Node command bridge
helper body into `ModelMountCore::plan_read_projection`, and the bridge now
acts only as command transport for projection kinds while the duplicated
bridge-local projection planner/helper tree is removed; that Rust-owned
projection implementation now lives in `model_mount/read_projection.rs` behind
the `ModelMountCore` facade so future Rust-core projection/API cuts do not
accumulate in the broad model-mount kernel file;
the route-facing skill/hook, model catalog/capability, repository workflow,
runtime account/node/tool, and doctor-report daemon-store delegates have been
deleted rather than preserved as inert compatibility wrappers;
the mounted thread-turn surface now fails closed for missing non-runtime resume
and turn-create Rust boundaries before JS agent status mutation, run creation,
or turn projection can become accepted truth, while diagnostics-blocked turn
creation enters the Rust-planned run-create path and returns the Rust turn
projection instead of the retired diagnostics-block refusal route;
public usage, public authority-evidence, and `/api/v1` authority-evidence /
workflow-capability preflight routes now call the mounted lifecycle projection
surface, where Rust replays Agentgres state instead of the JS run-read cache;
and reload no longer reads JS agent state before fail-closed admission;
agent/thread memory write, edit, delete, policy, status, and validation routes
also call the mounted thread-memory surface directly before daemon-store
pass-through wrappers, with write/edit/delete/policy requiring Rust
`plan_runtime_memory_control` plus Rust Agentgres memory-state commit before
returning route projections and status/validation/direct event append requiring
Rust `plan_runtime_memory_control` event planning plus Rust runtime-event
admission; workflow-edit proposal/apply controls require Rust
`plan_runtime_workflow_edit_control` and Rust runtime-event admission before
accepted control truth can return; diagnostics repair decision execution and
direct decision-event append require Rust `plan_runtime_diagnostics_repair_control`
and Rust runtime-event admission before accepted repair control truth can return,
and diagnostics repair decision resolution requires Rust
`project_runtime_diagnostics_repair_projection` over runtime `state_dir`
Agentgres event replay before accepted repair projection truth can return;
diagnostics operator override execution requires Rust
`plan_diagnostics_operator_override_state_update` to derive the override
approval state from canonical request/decision/policy context plus Rust
Agentgres run-state admission before accepted override control truth can return;
thread fork now calls Rust daemon-core `plan_runtime_thread_fork_control`,
commits only the Rust-authored forked agent through Agentgres-backed
`writeAgent`, validates the forked-thread projection, and admits only the
Rust-authored `thread.forked` runtime event; workspace-change inspection and run
cancel routes call mounted auxiliary surfaces instead of daemon-store
pass-through wrappers while direct Rust daemon-core projection and admission APIs
are extracted; managed-session inspection/control now calls the Rust daemon-core
managed-session projection/control planner and admits only the Rust-authored
control event;
thread resume, turn create, interrupt, and steer routes now call
the mounted thread-turn surface directly instead of daemon-store route
pass-through wrappers while store methods remain temporary internal delegates
until direct Rust daemon-core turn admission and stable protocol APIs own that
surface. This is a
larger-cut migration seam, not terminal architecture: the command transport
including transitional Node bridge operations, JS edge error translation,
remaining internal descriptor helpers, and remaining
internal agent/thread/run list/get, usage, turn, event/replay, trace, and
artifact helpers plus internal memory and conversation-artifact projection
helpers are scaffolding only until Rust daemon-core catalog, lifecycle, agent/run
admission, memory admission/projection, durable managed-session
storage/replay/projection, workspace-change control, durable thread-fork
storage/replay/projection, run-cancel admission, runtime thread/turn control, and
conversation-artifact projection over Agentgres-admitted truth,
ArtifactRef/PayloadRef binding where needed, wallet/network and cTEE authority
where required, receipt/state-root binding, replay, and stable IDE/CLI/SDK
protocol APIs own the surfaces end to end.
Thread-tool invocation routes now also call the mounted coding-tool invocation
surface directly instead of the daemon-store `invokeThreadTool()` pass-through,
and post-edit diagnostics feedback now invokes `lsp.diagnostics` through that
mounted surface too. The daemon-store `invokeThreadTool()` wrapper is retired,
but the mounted JS surface and command transport remain migration scaffolding
until direct Rust daemon-core StepModuleRouter/workload-client APIs own dispatch
end to end.

Slice 1035 originally moved the policy projection-required refusal owner family
for skill/hook registry, repository workflow, runtime tool catalog, and runtime
lifecycle projections out of the broad Rust `policy.rs` facade. That
intermediate refusal-owner lane is now superseded for those public projection
families by positive Rust daemon-core APIs in `skill_hook_registry.rs`,
`repository_workflow.rs`, `runtime_tool_catalog.rs`, and
`runtime_lifecycle.rs`. Resume by replacing the remaining temporary runner
transport with direct Rust daemon-core projection/admission APIs over
Agentgres-admitted truth, wallet.network/cTEE authority where applicable,
receipt/state-root binding, replay, and stable IDE/CLI/SDK protocol APIs.
Schedule a matrix-compaction pass after the next larger Rust-core extraction or
facade-retirement seam is clear.

Slice 1036 moves the run-cancel policy owner family out of the broad Rust
`policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`. The child
module owns run-cancel state-update and admission-required request/record/error
types, planner cores, validation, cancellation helper planning, and focused
proof tests; the parent facade only re-exports the surface. This preserves the
larger pure-Rust extraction direction while keeping the current JS
run-cancel facade, context-policy runner, and Node command bridge explicitly
non-terminal. Resume by replacing that transport path with direct Rust
daemon-core cancellation admission/persistence over Agentgres expected
heads/state roots, receipt/event materialization, replay, projection, and
stable IDE/CLI/SDK protocol APIs.

Slice 1037 moves the coding-tool budget recovery policy owner family out of
the broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`.
The child module owns budget-recovery state-update and control
request/record/error types, planner cores, validation, helper operator-control
planning, and focused proof tests; the parent facade only re-exports the
surface. This is an extraction toward the pure Rust daemon-core substrate, not
the terminal budget recovery architecture. The current JS coding-tool budget
recovery facade, JS context-policy runner, and Node command bridge remain
temporary migration transport. Resume by replacing that transport path with
direct Rust daemon-core budget recovery persistence over wallet
authority, Agentgres expected heads/state roots, policy receipts,
retry-event materialization, replay, projection, and stable IDE/CLI/SDK
protocol APIs.

Slice 1038 moves the operator-control policy owner family out of the broad
Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`. The
child module owns diagnostics operator override, operator interrupt, and
operator steer state-update request/record/error types, planner cores,
validation, helper operator-control planning, and focused proof tests; the
parent facade only re-exports the surfaces. This is a larger Rust ownership
cut across two public controls, not terminal operator-control migration. The
current JS diagnostics repair facade, JS operator turn facade, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core operator-control admission/persistence over wallet authority,
runtime control custody, Agentgres expected heads/state roots, receipts/events,
replay, projection, and stable IDE/CLI/SDK protocol APIs.

Slice 1039 moves the thread/run lifecycle policy owner family out of the
broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs`. The
child module owns thread-control, agent create, run create, agent status,
runtime-bridge thread start, runtime-bridge turn run, and subagent record
state-update request/record/error types, planner cores, validation, model-route
alias rejection, subagent parent-thread mismatch rejection, and focused proof
tests; the parent facade only re-exports the surfaces. This is a larger
Rust ownership cut across lifecycle, runtime-bridge, and subagent state
planning, not terminal lifecycle migration. The current JS thread-control
facade, agent/run lifecycle facade, runtime-bridge thread facade, subagent
facade, JS context-policy runner, and Node command bridge remain temporary
migration transport. Resume by replacing those transport paths with direct
Rust daemon-core lifecycle admission/persistence over wallet authority,
cTEE policy where private workspace custody is involved, Agentgres expected
heads/state roots, receipts/events, replay, projection, and stable IDE/CLI/SDK
protocol APIs. Schedule a matrix-compaction pass for Slices 1035-1039 once the
next larger Rust-core extraction/facade-retirement seam is clear.

Slice 1040 moves the context lifecycle policy owner family out of the broad
Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`. The
child module owns context-budget policy, coding-tool budget policy,
compaction-policy, context-compaction plan, and context-compaction state-update
request/record/error types, planner/evaluator cores, validation, helper
planning, canonical context-compaction payload shaping, and focused proof
tests; the parent facade only re-exports the surfaces. This is a larger
Rust ownership cut across context policy and compaction planning, not terminal
context-policy migration. The current JS context-policy facade, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core context admission/persistence over wallet authority where policy
exits require it, Agentgres expected heads/state roots, policy receipts,
context-compaction events, replay, projection, and stable IDE/CLI/SDK protocol
APIs. Keep the scheduled matrix-compaction pass for Slices 1035-1040 pending
until the next larger Rust-core extraction/facade-retirement seam is clear.

Slice 1041 moves the MCP/memory policy owner family out of the broad Rust
`policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`. The child
module owns MCP control state-update, MCP server validation, MCP validation
input projection, MCP manager validation/status/catalog/catalog-summary
projection, memory manager validation/status projection, and thread-memory
state-update request/record/error types, planner/projector cores, validation,
MCP catalog and memory projection helper logic, and focused proof tests; the
parent facade only re-exports the surfaces. This is a larger Rust ownership cut
across MCP and memory projection/control policy, not terminal MCP or memory
migration. The current JS MCP control/catalog/serve facades, JS thread-memory
surface, JS context-policy runner, and Node command bridge remain temporary
migration transport. Resume by replacing those transport paths with direct
Rust daemon-core MCP and memory admission/projection APIs over wallet authority
for external exits, cTEE custody where private workspace memory is involved,
Agentgres expected heads/state roots, MCP/memory receipts/events, replay,
projection, and stable IDE/CLI/SDK protocol APIs. Keep the scheduled
matrix-compaction pass for Slices 1035-1041 pending until the next larger
Rust-core extraction/facade-retirement seam is clear.

Slice 1042 moves the workflow-edit and diagnostics-repair admission-required
owner family out of the broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/admission_required.rs`. The
child module owns the workflow-edit and diagnostics-repair
admission-required request/record/error types, planner cores, validation,
canonical detail shaping, and focused proof tests; the parent facade only
re-exports the surfaces. This finishes the current policy facade split: broad
`policy.rs` now carries shared policy constants, `PolicyEvaluationRecord`,
module declarations, and re-exports rather than owning migrated hot-path
planner cores. This is still not terminal workflow-edit or diagnostics-repair
migration. The current JS workflow-edit/diagnostics-repair facades, JS
context-policy runner, and Node command bridge remain temporary migration
transport. Resume by replacing those transport paths with direct Rust
daemon-core workflow-edit and diagnostics-repair admission/persistence APIs
over wallet approval authority where applicable, Agentgres expected
heads/state roots, proposal/apply/repair receipts and events, replay,
projection, and stable IDE/CLI/SDK protocol APIs. Run the scheduled
matrix-compaction pass for Slices 1035-1042 once the next larger Rust-core
extraction/facade-retirement seam is clear.

Slice 1043 moves the workflow-edit and diagnostics-repair admission-required
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/policy_command.rs`. The service
owner remains `policy/admission_required.rs`; the bridge child module is only
fixed migration transport that translates the Rust-authored refusal records at
the process boundary. The conformance guard now proves the policy owner stays
out of the broad `policy.rs` facade and the admission-required command wrappers
stay out of the broad bridge module. This satisfies the scheduled
matrix-compaction pass for Slices 1035-1042, while preserving their
non-terminal status. Resume by replacing this command transport with direct
Rust daemon-core workflow-edit and diagnostics-repair admission/persistence
APIs over wallet approval authority where applicable, Agentgres expected
heads/state roots, proposal/apply/repair receipts and events, replay,
projection, and stable IDE/CLI/SDK protocol APIs.

Slice 1044 moves the coding-tool approval manifest and approval
request/decision/revoke state-update daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into `crates/node/src/bin/ioi_step_module_bridge/approval_command.rs`.
The approval authority owner remains
`crates/services/src/agentic/runtime/kernel/approval.rs`; the bridge child
module is only fixed migration transport that translates Rust-authored
approval authority records at the process boundary. The conformance guard now
proves the approval command wrappers stay out of the broad bridge module.
This is not terminal approval migration. Resume by replacing this command
transport with direct Rust daemon-core approval authority/admission/persistence
APIs over wallet.network grants, Agentgres expected heads/state roots,
approval receipts/events, replay, projection, and stable IDE/CLI/SDK protocol
APIs.

Slice 1045 moves the context-budget policy, coding-tool budget policy,
compaction policy, context-compaction plan, and context-compaction state-update
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/context_policy_command.rs`. The
context lifecycle policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`; the
bridge child module is only fixed migration transport that translates
Rust-authored context policy records at the process boundary. The conformance
guard now proves the context lifecycle command wrappers stay out of the broad
bridge module. This is not terminal context-policy migration. Resume by
replacing this command transport with direct Rust daemon-core context
admission/persistence/projection APIs over wallet authority where applicable,
Agentgres expected heads/state roots, policy receipts/events, replay, and
stable IDE/CLI/SDK protocol APIs.

Slice 1046 moves the MCP control state-update, MCP server validation, MCP
validation input projection, MCP manager status/validation/catalog/catalog
summary projection, memory manager status/validation projection, and
thread-memory state-update daemon-core command wrappers out of the monolithic
Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport
into `crates/node/src/bin/ioi_step_module_bridge/mcp_memory_command.rs`. The
MCP/memory policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
MCP and memory policy records at the process boundary. The conformance guard
now proves the MCP/memory command wrappers stay out of the broad bridge
module. This is not terminal MCP or memory migration. Resume by replacing this
command transport with direct Rust daemon-core MCP and memory
admission/projection/persistence APIs over wallet authority for external
exits, cTEE custody where private workspace memory is involved, Agentgres
expected heads/state roots, MCP/memory receipts/events, replay, projection,
and stable IDE/CLI/SDK protocol APIs.

Slice 1047 moves the thread-control, runtime-bridge thread-start, runtime
bridge turn-run, subagent record, agent create, agent status, and run create
state-update daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/thread_lifecycle_command.rs`. The
thread/run lifecycle policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs`; the
bridge child module is only fixed migration transport that translates
Rust-authored lifecycle policy records at the process boundary. The
conformance guard now proves the thread lifecycle command wrappers stay out of
the broad bridge module. This is not terminal lifecycle migration. Resume by
replacing this command transport with direct Rust daemon-core lifecycle
admission/persistence/projection APIs over wallet authority and cTEE policy
where applicable, Agentgres expected heads/state roots, lifecycle
receipts/events, replay, projection, StepModuleRouter dispatch where lifecycle
work enters admitted module execution, and stable IDE/CLI/SDK protocol APIs.

Slice 1048 moves the coding-tool budget recovery state-update and
admission-required, diagnostics operator-override state-update, operator
interrupt/steer state-update, and run-cancel state-update/admission-required
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/runtime_control_command.rs`. The
policy owners remain
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`,
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`, and
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
runtime-control policy records at the process boundary. The conformance guard
now proves the runtime-control command wrappers stay out of the broad bridge
module. This is not terminal runtime-control migration. Resume by replacing
this command transport with direct Rust daemon-core budget-recovery,
operator-control, diagnostics-repair, and run-cancel
admission/persistence/projection APIs over wallet authority where applicable,
Agentgres expected heads/state roots, runtime-control receipts/events, replay,
projection, StepModuleRouter dispatch where control work enters admitted
module execution, and stable IDE/CLI/SDK protocol APIs.

Slice 1049 originally moved the skill/hook registry, repository workflow,
runtime tool catalog, and runtime lifecycle projection-required daemon-core
command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport. That
intermediate projection-required lane is now superseded for those public
projection families: `project_skill_hook_registry`,
`project_repository_workflow`, `project_runtime_tool_catalog`, and
`project_runtime_lifecycle` are positive Rust daemon-core APIs, and the
projection-required policy owner for those migrated public routes is retired.
Slice 1225 now supersedes the remaining runner transport for this public
projection family with typed direct Rust daemon-core APIs and retires the old
command operations, dispatch arms, and response wrappers. This is still not
terminal projection migration. Resume with direct Rust daemon-core projection
APIs for the remaining lifecycle/run-read storage/replay, doctor/readiness,
replay, and stable IDE/CLI/SDK surfaces over Agentgres-admitted truth,
receipt/state-root binding, wallet authority where applicable, and cTEE custody
where private workspace projection is involved.

Slice 1050 moves the workspace-restore apply-policy, preview/apply operations,
and workspace-snapshot capture daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/workspace_restore_command.rs`.
The workspace restore owner remains
`crates/services/src/agentic/runtime/kernel/workspace_restore.rs`; the bridge
child module is only fixed migration transport that translates Rust-authored
restore policy, operation, and snapshot capture records at the process
boundary. The conformance guard now proves the workspace-restore command
wrappers stay out of the broad bridge module. This is not terminal workspace
restore or snapshot migration. Resume by replacing this command transport with
direct Rust daemon-core workspace restore/snapshot admission, artifact
materialization, Agentgres expected-head/state-root persistence, receipts,
events, replay, projection, and stable IDE/CLI/SDK protocol APIs.

Slice 1051 moves the cTEE private workspace action, worker/service package
invocation admission, L1 settlement admission, and governed runtime-improvement
proposal admission daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/governed_admission_command.rs`.
The Rust owners remain `ctee`, `marketplace`, `settlement`, `evolution`,
`receipt_binder`, and Agentgres admission; the bridge child module is only
fixed migration transport that translates those Rust-owned records at the
process boundary. The conformance guard now proves these governed
admission/action command wrappers stay out of the broad bridge module. This is
not terminal for the broader governed authority/admission/receipt migration.
Subsequent cuts replace external capability authority, cTEE, worker/service
package invocation, L1 settlement, and governed proposal admission with typed
Rust daemon-core APIs; the remaining work is richer receipt/state-root binding,
Agentgres admission, replay, projection, stable IDE/CLI/SDK protocol surfaces,
and the same transport retirement for other route families.

Slice 1052 moves the Agentgres storage-write admission and runtime state commit
daemon-core command wrappers out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/agentgres_command.rs`. This also
moves the runtime-state local persistence helper functions used by those commit
wrappers out of the broad bridge module. The Agentgres owner remains
`crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`; the bridge
child module is only fixed migration transport that translates Rust-owned
admission and commit records at the process boundary. The conformance guard now
proves Agentgres command wrappers and bridge-local runtime-state write helpers
stay out of the broad bridge module. This is not terminal Agentgres migration.
Resume by replacing this command transport with direct Rust daemon-core
Agentgres admission, storage, persistence, replay, projection, and stable
IDE/CLI/SDK protocol APIs over expected heads, state roots, ArtifactRefs,
PayloadRefs, and receipts.

Slice 1053 moves the model_mount daemon-core command wrappers out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/model_mount_command.rs`. This
includes route-decision admission, invocation admission, provider execution,
provider invocation and stream planning, lifecycle/inventory/backend-process
planning, required-record planners, accepted-receipt head/transition planning,
invocation receipt binding, and read-projection wrappers. The Rust
owner remains `crates/services/src/agentic/runtime/kernel/model_mount.rs` and
its child modules, with receipt binding, StepModuleRouter admission,
Agentgres admission, and projection still called from Rust. The bridge child
module is only fixed migration transport that translates Rust-owned records at
the process boundary; it is not the long-term API. The conformance guard now
proves model_mount command structs and handlers stay out of the broad bridge
module while the bridge root keeps dispatch and proof tests. Resume by
replacing this command transport with direct Rust daemon-core model_mount APIs,
Agentgres-backed persistence/replay/projection, provider lifecycle/control,
and stable IDE/CLI/SDK protocol surfaces.

Slice 1054 moves the external capability exit authority daemon-core command
wrapper out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/authority_command.rs`. The Rust
owner remains `crates/services/src/agentic/runtime/kernel/authority.rs`; the
bridge child module is only fixed migration transport that translates the
Rust-owned wallet.network authority record at the process boundary. The
conformance guard now proves the authority command struct and handler stay out
of the broad bridge module while the bridge root keeps dispatch and proof
tests. This is not terminal authority migration. Resume by replacing this
command transport with direct Rust daemon-core wallet.network authority APIs,
authority receipts, Agentgres/state-root binding where capability exits become
meaningful transitions, replay, projection, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1055 moves the coding-tool StepModule command wrapper family out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/coding_tool_command.rs`. This
includes the StepModule bridge request, `run_coding_tool_step_module`, the
workspace status, git diff, file inspect/apply patch, test run, LSP
diagnostics, artifact read, tool-result retrieval, computer-use lease response
wrappers, and the Rust workload/StepModuleRouter/receipt-binder/Agentgres
admission/projection response binding. The lower-level workspace filesystem,
diagnostic subprocess, patch, and path helpers remain temporary bridge helper
plumbing in the root module until the next direct Rust daemon-core execution
API extraction. This is not terminal coding-tool migration. Resume by replacing
both the command transport and the remaining bridge helper plumbing with direct
Rust daemon-core coding-tool execution/admission APIs, Rust/WASM workload
module execution, Agentgres-backed persistence, receipt/state-root binding,
replay, projection, and stable IDE/CLI/SDK protocol surfaces.

Slice 1056 moved the lower-level coding-tool workspace filesystem, path,
diagnostic subprocess, test-run, and patch helper plumbing out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/coding_tool_helpers.rs`. The broad
bridge root then retained proof tests and child-module wiring, while the
coding-tool command transport imports helper plumbing from a dedicated Rust
sibling module and Slice 1057 moves temporary operation dispatch to
`bridge_dispatch.rs`.
Conformance then failed if the helper function bodies returned to the root
bridge. Slice 1141 later retires this helper module entirely. This was still
not terminal coding-tool migration and must not canonize the Node bridge shape.
Resume by replacing the broad bridge transport and JS command runner/caller
path with direct Rust daemon-core coding-tool execution/admission APIs and
Rust/WASM workload modules, then retiring JS invocation facades, readback
shims, duplicate truth paths, and any compatibility wrappers that survive the
verified Rust-core boundary.

Slice 1057 moves the StepModule/daemon-core command dispatch table and
schema-family classifier out of the monolithic Rust
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration transport into
`crates/node/src/bin/ioi_step_module_bridge/bridge_dispatch.rs`. The root
bridge now re-exports only the stdin response entry point and keeps child-module
wiring plus proof tests, while conformance fails if the operation match or
`is_daemon_core_operation` classifier returns to the root. This is still a
command-transport boundary, not terminal Rust daemon-core API ownership.
Resume by replacing the dispatch table with direct daemon-core protocol/API
entry points, retiring JS command callers/facades/readbacks, and binding
accepted work through Rust/WASM modules, Agentgres admission, receipt/state-root
binding, replay, projection, wallet.network authority, and cTEE custody.

Slice 1058 starts collapsing duplicated JS daemon-core command-runner spawn
scaffolding into
`packages/runtime-daemon/src/runtime-daemon-core-command-runner.mjs`. The
external capability authority, L1 settlement, governed improvement, and cTEE
private workspace runners now delegate empty-argv command invocation, mock
handling, JSON parsing, process failure mapping, and Rust rejection mapping to
that shared helper instead of each importing `node:child_process` and owning
local command-process semantics. Conformance now requires those runners to use
the shared helper and forbids direct child-process imports in them. This is a
JS-scaffolding reduction, not terminal API migration. Resume by moving the
remaining daemon-core runners onto the shared helper only as an intermediate
step, then replacing the shared command-runner helper itself with direct Rust
daemon-core protocol/API calls and retiring JS command facades/readbacks.

Slice 1059 extends that temporary shared command-runner helper to the
worker/service package, coding-tool approval, and approval-state runners. Those
runners no longer import `node:child_process` or own local JSON/process/Rust
rejection handling; conformance requires them to delegate to
`runtime-daemon-core-command-runner.mjs` while the helper keeps the fixed
empty-argv transport rule. This is still an intermediate scaffolding collapse,
not a canonical Node bridge. Resume by moving the remaining large daemon-core
runners onto the helper only where it reduces duplicate migration plumbing, then
cutting the helper itself over to direct Rust daemon-core protocol/API ownership
and retiring JS command facades, readback adapters, and compatibility wrappers
once Rust admission, Agentgres truth, receipt/state-root binding, replay,
projection, wallet.network authority, and cTEE custody are verified.

Slice 1060 extended the same temporary helper to the then-live runtime
Agentgres admission runner and workspace restore. That historical cut reduced
duplicated JS command transport on the Agentgres truth path and restore
planning/execution path, but the Agentgres runner side is now superseded by the
later mounted-core cut; do not recreate that shared command helper or runner
path. Resume by collapsing the remaining large context-policy, model-mount
admission, and StepModule command surfaces where helpful, then
replace the shared helper and Node command bridge with direct Rust daemon-core
protocol/API ownership.

Slice 1061 extends the temporary helper to the remaining large daemon-core
command runners: context policy and model-mount admission.
`runtime-context-policy-core.mjs` and
`model-mounting/model-mount-core.mjs` now delegate fixed empty-argv
command spawn, mock handling, JSON parsing, process failure mapping, and Rust
rejection mapping to `runtime-daemon-core-command-runner.mjs` instead of
importing `node:child_process` directly. This leaves the StepModule workload
runner as the only direct command-runner holdout, because it uses the
StepModule workload command schema rather than the daemon-core command schema.
Resume by making the StepModuleRouter/Rust workload boundary a deliberate
Rust-core cut, then replacing the shared daemon-core command helper and Node
command bridge with direct Rust daemon-core protocol/API ownership.

Slice 1062 removes the final runner-local command spawn from the StepModule
workload runner without treating the Node bridge as canonical architecture.
`packages/runtime-daemon/src/step-module-runner.mjs` now delegates the
temporary StepModule command-bridge transport to
`packages/runtime-daemon/src/step-module-command-runner.mjs`; the runner keeps
the Rust workload live contract, invocation projection, and fail-closed backend
selection behavior, but no longer imports `node:child_process` or owns the
spawn/JSON/Rust-rejection mechanics. Conformance now fails if the StepModule
runner regains direct child-process ownership, while the helper is explicitly
the remaining temporary process boundary for the distinct StepModule workload
schema. This is still not terminal StepModuleRouter migration. Resume by
replacing the StepModule command helper, the shared daemon-core command helper,
and the Node bridge with direct Rust daemon-core/workload protocol APIs,
Rust/WASM module execution, Agentgres admission, receipt/state-root binding,
replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces. Slice 1142 later retires the dedicated
StepModule command helper and collapses the remaining StepModule command
transport onto the shared temporary daemon-core command invoker.

Slice 1063 moved bridge command-envelope schema ownership out of the temporary
stdin dispatch transport and into the temporary bridge-envelope adapter at
`crates/node/src/bin/ioi_step_module_bridge/command_envelope.rs`. At that slice,
the adapter carried the StepModule command schema version, daemon-core command
schema version, expected-schema lookup, and daemon-core operation-family
classifier so `bridge_dispatch.rs` could keep only transport and schema checks.
This was an intermediate split, not canonical Rust ownership. Resume by
replacing bridge-envelope adapter ownership, the StepModule command helper, and
the shared daemon-core command helper with direct Rust daemon-core/workload
protocol APIs, while preserving Rust-owned StepModuleRouter dispatch, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1064 moves temporary bridge operation routing out of stdin/envelope
transport and into
`crates/node/src/bin/ioi_step_module_bridge/command_dispatch.rs`.
`bridge_dispatch.rs` now only reads stdin, parses the canonical envelope,
checks the Rust-owned command schema from `command_envelope.rs`, and calls
`dispatch_bridge_operation()`. The large operation match still exists as
temporary bridge routing, but it no longer lives in the process-envelope
transport. Conformance now fails if `bridge_dispatch.rs` regains the operation
table. This is still not terminal bridge retirement. Resume by replacing
`command_dispatch.rs`, `command_envelope.rs`, the StepModule command helper,
and the shared daemon-core command helper with direct Rust daemon-core/workload
protocol APIs over Rust/WASM execution, Agentgres admission, receipt/state-root
binding, replay, projection, wallet.network authority, cTEE custody, and
stable IDE/CLI/SDK protocol surfaces.

Slice 1065 moves command schema-family ownership out of the Node bridge adapter
and into Rust kernel protocol code at
`crates/services/src/agentic/runtime/kernel/command_protocol.rs`. The Rust
module now owns the StepModule command schema version, daemon-core command
schema version, expected-schema lookup, and daemon-core operation-family
classifier with Rust proof tests for StepModule and daemon-core operation
families. `ioi_step_module_bridge/command_envelope.rs` is now adapter-only and
re-exports the Rust kernel protocol for the remaining temporary Node bridge.
Conformance now fails if schema-family truth is redefined in the Node envelope,
dispatch transport, or broad bridge module. This is still not terminal bridge
retirement. Resume by replacing `command_dispatch.rs`, the adapter-only
`command_envelope.rs`, the StepModule command helper, and the shared
daemon-core command helper with direct Rust daemon-core/workload protocol APIs
over Rust/WASM execution, Agentgres admission, receipt/state-root binding,
replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces.

Slice 1066 makes Rust command protocol classification fail closed for unknown
bridge operations. `command_protocol.rs` now explicitly distinguishes known
StepModule operations, known daemon-core operations, and operations with no
schema family. `expected_command_schema_version()` returns no schema for an
unknown operation instead of implicitly treating it as a StepModule command, and
`bridge_dispatch.rs` rejects that operation before the temporary dispatch table
can run. Rust and bridge tests prove unknown operations have no schema family.
Conformance now fails if the bridge stops rejecting unknown operations before
dispatch or if Rust protocol ownership loses the StepModule/daemon-core/unknown
classification split. This is still not terminal bridge retirement. Resume by
replacing `command_dispatch.rs`, the adapter-only `command_envelope.rs`, the
StepModule command helper, and the shared daemon-core command helper with direct
Rust daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1067 makes the Rust kernel command protocol own the typed operation
family catalog instead of leaving that catalog implicit in the temporary bridge
dispatch table. `command_protocol.rs` now exposes `CommandFamily`,
`STEP_MODULE_OPERATIONS`, `DAEMON_CORE_OPERATIONS`, and `command_family()`;
the daemon-core catalog includes the full temporary bridge operation surface,
including workflow-edit admission and MCP/memory projection commands that were
previously dispatchable but not cataloged by Rust classification. The bridge
intake resolves the Rust-owned family before schema validation, and
`command_dispatch.rs` now dispatches on `(CommandFamily, operation)` so the
remaining Node command table consumes Rust protocol classification instead of
acting as an independent admissibility list. Rust tests prove every cataloged
operation has the expected schema family, and bridge tests prove unknown
operations have no Rust family. This is still not terminal bridge retirement:
the operation catalog belongs in Rust now, but the temporary Node dispatch
table, StepModule command helper, and shared daemon-core command helper still
must be replaced by direct Rust daemon-core/workload protocol APIs over
Rust/WASM execution, Agentgres admission, receipt/state-root binding, replay,
projection, wallet.network authority, cTEE custody, and stable IDE/CLI/SDK
protocol surfaces.

Slice 1068 moves command-envelope validation into the Rust kernel protocol.
`command_protocol.rs` now exposes `ValidatedCommandEnvelope`,
`CommandProtocolError`, and `validate_command_envelope()`, so the Rust
protocol layer owns both unknown-operation rejection and schema-family mismatch
rejection. The temporary bridge stdin transport now parses JSON, calls the
Rust validator, adapts the Rust protocol error into the bridge response shape,
and passes the Rust-owned `CommandFamily` into dispatch; it no longer rebuilds
`expected_schema_version` or `schema_version_invalid` logic locally.
Conformance now fails if schema-version validation drifts back into
`bridge_dispatch.rs` or if Rust loses the typed envelope validator and mismatch
tests. This is still not terminal bridge retirement: the remaining Node command
dispatch table, adapter-only command envelope, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1069 retires the adapter-only bridge command-envelope wrapper. After
Slices 1065-1068 moved schema versions, operation-family cataloging, and
envelope validation into `command_protocol.rs`,
`crates/node/src/bin/ioi_step_module_bridge/command_envelope.rs` only
re-exported Rust protocol symbols and had become compatibility scaffolding.
The wrapper file and `mod command_envelope` declaration are now removed, and
the remaining bridge transport imports `validate_command_envelope()` and
command protocol symbols directly from
`ioi_services::agentic::runtime::kernel::command_protocol`. Conformance now
fails if the adapter-only wrapper returns or if the bridge stops using the
Rust protocol module directly. This is still not terminal bridge retirement:
the remaining Node command dispatch table, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1070 moves temporary bridge operation identity into the Rust command
protocol. `command_protocol.rs` now exposes a typed `CommandOperation`, maps
every StepModule and daemon-core operation string to that Rust enum, round-trips
catalog entries through `CommandOperation::as_str()`, and returns the typed
operation from `ValidatedCommandEnvelope`. The stdin bridge still parses the
wire envelope, but it now dispatches on `validated.command_operation`; the
bridge-local dispatch module no longer matches `(CommandFamily, operation)` raw
strings or carries an unsupported string fallback. Conformance now fails if the
bridge reintroduces raw operation-string routing or if Rust loses the typed
operation identity and tests. This is still not terminal bridge retirement: the
remaining `command_dispatch.rs` function table, StepModule command helper, and
shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1071 moves temporary bridge envelope parsing into the Rust command
protocol. `command_protocol.rs` now owns the deserializable `CommandEnvelope`
wire shape with canonical `schema_version` plus operation fields, exposes
`validate_command_envelope_payload()`, and tests that the retired
`schemaVersion` alias cannot satisfy command intake. The stdin bridge still
reads bytes and parses JSON transport, but it no longer declares a bridge-local
`BridgeEnvelope`; it deserializes the Rust protocol envelope and passes it back
to Rust validation before dispatching on the Rust-owned `CommandOperation`.
Conformance now fails if a bridge-local envelope struct returns or if the
bridge stops using the Rust envelope/payload validator. This is still not
terminal bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1072 retires duplicate bridge-local envelope identity checks from the
authority, admission-required policy, and projection-required command wrappers.
Because `bridge_dispatch.rs` now deserializes the Rust `CommandEnvelope`, calls
the Rust payload validator, and dispatches by Rust `CommandOperation`, these
child wrappers no longer carry local `schema_version` or `operation` fields and
no longer own `schema_version_invalid` or `operation_unsupported` branches.
They deserialize only body-specific backend/request fields before entering the
Rust authority and policy cores. Conformance now fails if those local envelope
checks return to `authority_command.rs`, `policy_command.rs`, or
`projection_command.rs`, and the schema-family mismatch proof now lives at the
Rust command protocol validator boundary. This is still not terminal bridge
retirement: the remaining `command_dispatch.rs` function table, StepModule
command helper, and shared daemon-core command helper must still be replaced by
direct Rust daemon-core/workload protocol APIs over Rust/WASM execution,
Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1073 retires the same duplicate bridge-local envelope identity checks
from the governed-admission command wrappers for cTEE private workspace
execution, worker/service package invocation, L1 settlement admission, and
governed runtime-improvement proposal admission. Those wrappers no longer carry
local `schema_version` or `operation` fields and no longer own local
`schema_version_invalid` or `operation_unsupported` branches; they deserialize
only the body-specific backend/invocation/request/attempt/proposal fields
before entering the Rust cTEE, marketplace, settlement, receipt-binder,
Agentgres admission, and governed-evolution cores. The StepModule-schema
rejection proofs for those operations now live at the Rust command protocol
validator boundary. Conformance now fails if the governed-admission child
module regains local command-envelope identity. This is still not terminal
bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1074 retires duplicate bridge-local envelope identity checks from the
approval and workspace-restore command wrappers. The approval child module no
longer carries local `schema_version` or `operation` fields for coding-tool
approval manifests or approval request/decision/revoke state-update planning,
and the workspace-restore child module no longer carries those fields for
apply-policy planning, preview/apply operations, or snapshot capture. The
wrappers now deserialize only body-specific backend/request fields before
entering the Rust approval and workspace-restore cores. The StepModule-schema
rejection proofs for those operations now live at the Rust command protocol
validator boundary. Conformance now fails if approval or workspace-restore
child modules regain local command-envelope identity. This is still not
terminal bridge retirement: the remaining `command_dispatch.rs` function table,
StepModule command helper, and shared daemon-core command helper must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
execution, Agentgres admission, receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1075 retires duplicate bridge-local envelope identity checks from the
context-policy, runtime-control, thread-lifecycle, and MCP/memory command
wrappers. Those child modules no longer carry local `schema_version` or
`operation` fields and no longer own local `schema_version_invalid` or
`operation_unsupported` branches for budget policy, compaction policy,
context-compaction state updates, operator/runtime-control updates, run cancel
gates, runtime bridge thread/run state updates, agent/run lifecycle updates,
MCP control, MCP validation/projection, memory projection, or thread-memory
state updates. They deserialize only body-specific backend/request fields
before entering the Rust policy cores. The representative StepModule-schema
rejection proofs for those families now live at the Rust command protocol
validator boundary. Conformance now fails if any of those child modules regain
local command-envelope identity. This is still not terminal bridge retirement:
the remaining `command_dispatch.rs` function table, StepModule command helper,
and shared daemon-core command helper must still be replaced by direct Rust
daemon-core/workload protocol APIs over Rust/WASM execution, Agentgres
admission, receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody, and stable IDE/CLI/SDK protocol surfaces.

Slice 1076 retires duplicate bridge-local envelope identity checks from the
Agentgres command wrapper. `agentgres_command.rs` no longer carries local
`schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for storage-backend
write admission or runtime run/agent/memory/subagent/artifact/model-mount
record and receipt state commits. The wrapper now deserializes only
body-specific backend/state-dir/request fields before entering the Rust
Agentgres admission core and persistence helpers. The representative
StepModule-schema rejection proofs for Agentgres admission and commit
operations now live at the Rust command protocol validator boundary.
Conformance now fails if the Agentgres child module regains local
command-envelope identity. This is still not terminal bridge retirement:
Agentgres admission and persistence semantics are Rust-owned, but the remaining
`command_dispatch.rs` function table, shared daemon-core command helper, and
JS command callers must still be replaced by direct Rust daemon-core protocol
APIs over Agentgres-admitted truth, receipt/state-root binding, replay,
projection, wallet.network authority, cTEE custody, and stable IDE/CLI/SDK
protocol surfaces.

Slice 1077 retires duplicate bridge-local envelope identity checks from the
model-mount command wrapper. `model_mount_command.rs` no longer carries local
`schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for route
decision, invocation admission, provider execution, provider invocation and
stream invocation, provider lifecycle and inventory, instance lifecycle,
provider-result admission, backend-process planning, backend/server/runtime/
tokenizer/route-control required records, accepted-receipt head and transition
planning, invocation receipt binding, or read projection. The wrapper now
deserializes only body-specific backend/request/invocation/result/head fields
before entering the Rust model_mount core, StepModuleRouter, ReceiptBinder,
Agentgres admission, and Rust projection cores. The model-mount runtime schema
constant remains only for Rust-authored route-selection receipt payload output;
it is no longer command-envelope identity.

The representative StepModule-schema rejection proofs for model-mount route
decision, provider invocation, receipt binding, and read projection now live at
the Rust command protocol validator boundary. Conformance now fails if the
model-mount child module regains local command-envelope identity. This is
still not terminal bridge retirement: `command_dispatch.rs`, the shared
daemon-core command helper, JS command callers, and model-mount JS facades must
still be replaced by direct Rust daemon-core/model_mount protocol APIs over
Rust/WASM workload execution, Agentgres-admitted truth, receipt/state-root
binding, replay, projection, wallet.network authority, cTEE custody, and stable
IDE/CLI/SDK protocol surfaces.

Slice 1078 retires duplicate bridge-local envelope identity checks from the
coding-tool StepModule command wrapper. `coding_tool_command.rs` no longer
carries local `schema_version` or `operation` fields and no longer owns local
`schema_version_invalid` or `operation_unsupported` branches for
`run_coding_tool_step_module`. The wrapper now deserializes only
body-specific backend, invocation, workspace-root, and input fields before
entering StepModule invocation validation, StepModuleRouter admission,
Rust workload-client dispatch planning, receipt binding, Agentgres admission,
projection binding, and the Rust-live coding-tool handlers.

The StepModule schema-family rejection proof for coding-tool execution now
lives at the Rust command protocol validator boundary:
`validate_command_envelope()` rejects `run_coding_tool_step_module` when it is
sent with the daemon-core command schema. Conformance now fails if the
coding-tool StepModule wrapper regains local command-envelope identity. This is
still not terminal bridge retirement: `command_dispatch.rs`, the StepModule
command helper, JS command callers, and coding-tool JS facades must still be
replaced by direct Rust daemon-core/workload protocol APIs over Rust/WASM
module execution, Agentgres-admitted truth, receipt/state-root binding, replay,
projection, wallet.network authority where applicable, cTEE custody where
applicable, and stable IDE/CLI/SDK protocol surfaces.

Slice 1079 retires duplicate camelCase model-route projection fields from the
runtime thread-control model envelope. `initialThreadRuntimeControls()` and
`normalizedAgentRuntimeControls()` now emit canonical `route_id`,
`selected_model`, `endpoint_id`, `provider_id`, `receipt_id`,
`reasoning_effort`, `max_cost_usd`, `workflow_graph_id`, `workflow_node_id`,
and `updated_at` fields without parallel `routeId`, `selectedModel`,
`endpointId`, `providerId`, `receiptId`, `reasoningEffort`, `maxCostUsd`,
`workflowGraphId`, `workflowNodeId`, or `updatedAt` aliases. The normalized
runtime-control model reader also stops treating those retired model-control
aliases as persisted truth.

This slice does not complete thread-control migration: the JS surface remains
fail-closed/migration scaffolding until direct Rust daemon-core thread-control
admission, Agentgres state-root binding, replay, and projection APIs own the
surface. It does, however, remove a duplicate projection shape that could have
survived as a compatibility contract beside the Rust-owned snake_case protocol.

Slice 1080 retires the Rust policy-boundary request alias that allowed
`modelRoute` to satisfy the canonical `model_route` field for thread-control
state-update planning. `ThreadControlAgentStateUpdateRequest` now accepts only
the canonical snake_case request field; a retired camelCase `modelRoute` input
deserializes as unknown request data and fails closed before the Rust planner
can produce a thread-control state-update plan.

Conformance now fails if the Rust thread-lifecycle policy regains
`#[serde(alias = "modelRoute")]` or if the focused Rust proof for the retired
request alias disappears. This is still not terminal thread-control migration:
the command transport and JS fail-closed facade remain temporary scaffolding.
The intended long-term shape is direct Rust daemon-core thread-control
admission, Agentgres expected-head/state-root binding, replay, projection, and
stable protocol APIs without compatibility request aliases.

Slice 1081 retired RuntimeAgentService bridge command/input alias tolerance at
both migration edges while the bridge still existed. Slice 1251 supersedes that
interim guard: the JS command adapter, Rust bridge binary, bridge env policy
override, and bridge-backed proof scripts are now deleted. Runtime-service
execution remains non-terminal until direct Rust daemon-core runtime
thread/turn/control APIs own admission, execution dispatch, persistence,
replay, projection, wallet/cTEE policy, and Agentgres expected-head/state-root
binding.

Slice 1082 retires the daemon-store thread-turn and thread-control compatibility
delegates that remained after public routes moved to mounted surfaces. The
store no longer exposes `resumeThread()`, `createTurn()`, `interruptTurn()`,
`steerTurn()`, `updateThreadRuntimeControls()`, or
`appendThreadRuntimeControlEvent()` as pass-through methods. Route handlers and
tests now enter through `threadTurnSurface` or `threadControlSurface` directly,
so runtime thread/turn/control admission cannot re-enter through a daemon-store
compatibility API.

Conformance now fails if those store delegates return in `index.mjs`, if
operator turn-control tests stop proving the store methods are absent, or if
runtime-backed turn tests stop using the mounted turn surface. This is still not
terminal thread/turn/control migration: the mounted JS surfaces remain
fail-closed or fixed transport scaffolding until direct Rust daemon-core
admission, execution dispatch, persistence, replay, projection, wallet/cTEE
policy, and Agentgres expected-head/state-root binding own the surface.

Slice 1083 moved the public operator turn-control admission-required refusal
contract into the Rust policy core. That intermediate fail-closed public
facade is now retired for normal interrupt/steer execution: public operator
interrupt calls Rust `plan_operator_interrupt_state_update`, public operator
steer calls Rust `plan_operator_steer_state_update`, the JS surface validates
the Rust-planned operator-control envelope and run projection, resolves the
current run through the mounted run resolver, and persists only the Rust-planned
run through Agentgres-backed `writeRun` before returning route truth. The Rust
`OperatorTurnControlAdmissionRequiredCore` still owns the canonical
`runtime_operator_turn_control_rust_core_required` record for missing Rust
state-update planning, so absence of the Rust boundary fails closed before any
JS runtime bridge control, event append, or local run mutation can execute.

Conformance now fails if the operator turn-control required-boundary envelope
is authored only in JS, if the Rust state-update command operations are removed
from typed command dispatch, if public interrupt/steer stop invoking the Rust
state-update planners before Agentgres run persistence, if direct runtime
bridge control/event append returns, or if camelCase detail aliases return on
the missing-boundary refusal details. This remains non-terminal: command
transport, wallet/runtime-control authority, Agentgres expected-head/state-root
commit depth, replay/projection storage, and stable protocol APIs must still
become direct Rust daemon-core surfaces.

Slice 1084 moved the public non-runtime thread-turn admission-required refusal
contract into the Rust thread-lifecycle policy core. Slice 1280 supersedes the
temporary mounted lifecycle surface: missing direct Rust lifecycle APIs still
fail closed, while normal public non-runtime resume calls the direct
Rust-backed agent status-control API and returns the Rust thread projection, and
normal public non-runtime turn creation calls the direct Rust-backed run-create
API and returns the Rust turn projection.
Slice 1260 supersedes the earlier diagnostics-blocked exception: blocking
diagnostics feedback now travels through the same Rust-planned run-create path,
and `ThreadTurnAdmissionRequiredCore` rejects the retired diagnostics-block
operation instead of preserving a separate refusal lane. Direct JS
`updateAgent()`, `createRun()`, JS turn projection composition, runtime-event
append, and daemon-store pass-through wrappers stay retired from the
thread-turn surface.

Conformance now fails if the thread-turn required-boundary envelope is authored
only in JS, if the typed Rust daemon-core boundary drifts back into broad
command-wrapper plumbing, if the public non-runtime path re-enters direct JS
mutation wrappers, or if diagnostics-blocked turn creation re-enters the
retired admission-required refusal path instead of Rust run-create planning.
This remains non-terminal: direct Rust daemon-core thread-turn protocol APIs,
durable replay/projection storage, and command transport retirement still need
Rust ownership across the remaining lifecycle edges.

Slice 1085 moves the public agent/run lifecycle admission-required refusal
family into the Rust thread-lifecycle policy core. The Rust
`LifecycleAdmissionRequiredCore` now owns the canonical required-boundary
records for agent creation, top-level thread creation, run creation, agent
status control, and permanent agent deletion, and the daemon-core command
protocol exposes them through
`plan_lifecycle_admission_required`. The JS agent/run lifecycle and thread
store surfaces consume these Rust-authored records while still failing closed
before JS route/model/memory planning, agent lookup where forbidden, `writeRun`,
`writeAgent`, agent/run map mutation, or Agentgres commit.

Conformance now fails if these lifecycle required-boundary envelopes are
authored only in JS, if the typed Rust command operation is removed, if the
temporary Node command wrapper moves back into the broad bridge module, or if
the JS surfaces stop proving they called the Rust admission-required planner
before any retired state-update or persistence path. This remains
non-terminal: direct Rust daemon-core lifecycle admission, wallet/cTEE policy
where applicable, Agentgres expected-head/state-root commit, replay,
projection, and stable protocol APIs must still replace the temporary command
transport.

Public agent status-control state updates are now a positive Rust
daemon-core path. Public archive/unarchive/resume/close/reload call Rust
`plan_agent_status_state_update`; JS supplies the current agent and requested
status facts, requires a Rust-returned agent projection with the requested
operation kind, and persists only that Rust-authored projection through the
Agentgres-backed `writeAgent` commit path.

Public agent creation is now a positive Rust daemon-core path. `createAgent()`
requires Rust `plan_agent_create_state_update` before JS can persist any
candidate provider/model-route/MCP/runtime-control facts, rejects missing Rust
agent projection, mismatched operation kind, or incomplete identity/timestamp
output, and persists only the Rust-returned `agent.create` projection through
the Agentgres-backed `writeAgent` commit path. Direct `agents` map mutation
remains retired.

Public agent-scoped run creation is now a positive Rust daemon-core path.
`createRun()` requires Rust `plan_run_create_state_update` before JS can look
up the agent, resolve provider/model-route/memory facts, construct the canonical
run candidate, assemble usage envelopes, or persist anything. JS requires a
Rust-returned `run.create` projection with complete identity/timestamp output,
persists only that projection through the Agentgres-backed `writeRun` commit
path, keeps direct `runs` map mutation retired, and ignores retired
thread/approval plus diagnostics request aliases. Missing Rust planner support
still fails closed before lookup, route, memory, or persistence.

Public top-level thread creation is now a positive Rust daemon-core path.
`createThread()` requires Rust `plan_thread_create_state_update` before JS can
route model/provider/MCP/runtime-control candidate facts or persist anything.
JS requires Rust-returned `agent` and `thread` projections with matching
identity, persists only the Rust-authored `thread.create` agent projection
through the Agentgres-backed `writeAgent` commit path, emits the thread-start
projection through the Rust thread-event surface, and returns only the Rust
thread/turn projection record. Missing Rust planner support still fails closed
before route planning or persistence. Runtime-service thread start is now a
separate positive Rust bridge-start boundary: it requires
`plan_runtime_bridge_thread_start_agent_state_update`, commits only the
Rust-planned bridge agent through Agentgres `writeAgent`, and returns the Rust
thread projection. Runtime-service thread control is now a paired Rust
bridge-control boundary: it requires
`plan_runtime_bridge_thread_control_agent_state_update`, commits only the
Rust-planned `thread.runtime_bridge.control` agent through Agentgres
`writeAgent`, and returns the Rust thread projection without dispatching the
deleted JS bridge `controlThread` path. Runtime-service turn submit is now a
paired Rust bridge-turn boundary: it requires
`plan_runtime_bridge_turn_run_state_update`, commits only the Rust-planned
`turn.runtime_bridge.submit` run through Agentgres `writeRun`, and returns the
Rust turn projection without dispatching the deleted JS bridge `submitTurn`
path.

Public permanent agent deletion is now a positive Rust daemon-core path.
`deleteAgent()` calls Rust `plan_agent_delete_state_update`; JS supplies only
the current agent fact, requires a Rust-returned `agent.delete` tombstone with
`status: deleted` and `deletedAt`, and persists only that tombstone through the
Agentgres-backed `writeAgent` commit path. Wallet/retention authority,
lifecycle replay/projection, and stable lifecycle protocol APIs remain
non-terminal.

Slice 1086 retires the `RuntimeDaemonStore.createAgent()`,
`RuntimeDaemonStore.createRun()`, and `RuntimeDaemonStore.createThread()`
compatibility pass-throughs. Public agent creation, top-level thread creation,
and agent-scoped run creation now enter direct Rust-backed lifecycle APIs; the
daemon store no longer exposes a second lifecycle creation method family that
can be mistaken for the canonical authority boundary after context compaction.

Conformance now fails if the daemon store re-imports the retired
`createAgentState`/`createRunState` helpers, reintroduces store-level
`createAgent()`/`createRun()`/`createThread()` wrappers, or routes public
agent/thread/run creation through the store compatibility layer instead of the
direct lifecycle APIs. Slice 1280 also makes conformance fail if the mounted
`agentRunLifecycleSurface` facade or `createRuntimeAgentRunLifecycleSurface`
export returns. This remains non-terminal: durable lifecycle replay/projection,
Agentgres expected-head/state-root binding, wallet/cTEE authority, and stable
protocol APIs still need terminal Rust-owned coverage.

Slice 1087 converts the stale `runtime-thread-control.test.mjs` live
runtime-service proof into bounded Rust-ownership evidence. That test no longer
tries to seed model routes through retired JS model-mount mutation facades or
exercise subagent recovery through removed daemon-store compatibility wrappers.
It proves that route seeding fails through the Rust model-mount route-control
required record, runtime-service thread creation uses Rust bridge-start state
planning and Agentgres agent commit before any JS runtime bridge `startThread`
dispatch, and the retired daemon-store lifecycle and thread-control/subagent
wrappers remain absent.

Conformance now fails if this test drifts back into JS runtime-service bridge
dispatch or if it stops checking the Rust-required route-control and runtime
bridge-start boundaries. Runtime-service thread control and turn submit have
since moved to Rust bridge-control/bridge-turn planning plus Agentgres
`writeAgent`/`writeRun`; managed-session inspection/control has now moved to
Rust managed-session projection/control planning plus runtime-event admission,
but durable managed-session storage/replay/projection and wallet/cTEE session
authority still need direct Rust daemon-core ownership before managed-session
live proof can become terminal. Subagent recovery still needs direct Rust
daemon-core admission, dispatch, Agentgres binding, replay, and projection
before it can become an active live proof again.

Slice 1088 deletes the obsolete Stage 5 stop/cancel/recover and Stage 7
delegation live-GUI proof scripts that still encoded JS model-mount
`importModel`/`mountEndpoint` setup plus JS runtime-service bridge dispatch as
successful product proof. Those scripts were self-contained, unreferenced by
the conformance suite, and contradicted the current Rust-required boundary
where model-route mutation and subagent recovery must fail closed until direct
Rust daemon-core admission and Agentgres binding exist; managed-session control,
runtime-service thread start, control, and turn submit are now positive
Rust-planned Agentgres-backed boundaries but still require durable replay,
projection, authority, and stable protocol ownership before terminal proof.

Conformance now fails if either retired live-GUI proof script is restored. New
live GUI proof for these scenarios must be introduced only after the Rust
daemon core owns the runtime-service/subagent execution path end to end and the
proof drives stable protocol APIs over the unified substrate.

Slice 1089 retires the remaining JS runtime-service bridge result and live-event
normalizers after the start, turn-submit, and control facades were already made
fail-closed. `RuntimeDaemonService` no longer exposes
`normalizeRuntimeBridgeThreadStart()`, `normalizeRuntimeBridgeTurnSubmit()`, or
`normalizeRuntimeBridgeLiveEvent()` pass-through methods, and
`runtime-bridge-thread.mjs` no longer carries the old bridge-result projection
helpers or camelCase payload scrubber.

Conformance now proves the runtime-service bridge normalizers stay absent
instead of treating them as compatibility evidence. The next positive
runtime-service proof must be Rust daemon-core admission, Agentgres
expected-head/state-root binding, replay, and projection over stable protocol
APIs; it must not restore JS bridge result shaping.

Slice 1090 removes the stale runtime-service bridge success-path fixtures from
`runtime-bridge-thread.test.mjs`. The fail-closed test no longer defines fake
RuntimeAgentService bridge objects, fake Rust planner delegates, fake in-flight
turn registration, fake event append, or fake agent/run persistence helpers; it
uses only inert call logs and verifies the start, turn-submit, and control
facades fail before any such operation could exist.

Conformance now rejects reintroducing fake bridge/planner/persistence helpers
into that negative-boundary proof. Positive runtime-service evidence must come
from the future direct Rust daemon-core path, not from resurrected JS bridge
success fixtures inside tests.

Slice 1091 removes stale conformance-parser scaffolding for the deleted
runtime-service bridge normalizers. The conformance suite no longer extracts
`normalizeRuntimeBridgeThreadStart()`, `normalizeRuntimeBridgeTurnSubmit()`, or
`normalizeRuntimeBridgeLiveEvent()` bodies from `runtime-bridge-thread.mjs`;
instead, the existing checks prove those names remain absent from the runtime
bridge module, daemon index, and focused tests.

This keeps the verifier aligned with the target architecture: deleted JS bridge
projection bodies must not remain encoded as parse targets inside conformance.

Slice 1092 retired the JS RuntimeAgentService command adapter. Slice 1251
finishes the substrate cut: `RuntimeApiBridge` no longer exports an adapter
class/factory, bridge command envs are absent from the profile helper, the
`ioi-runtime-bridge` binary is deleted, and daemon startup rejects
`runtimeBridge`. New positive runtime-service execution must land as direct
Rust daemon-core admission, Agentgres expected-head/state-root binding, replay,
and projection over stable protocol APIs.
Slice 1272 then deletes the bridge-named profile helper artifact itself:
`runtime-api-bridge.mjs` and its focused test are absent, live daemon imports
use `runtime-profile.mjs`, and conformance guards that the old bridge module
filename cannot return as a compatibility shim.

Slice 1093 retires the stale JS runtime-service bridge projection authoring
that survived after the command adapter and runtime bridge facades were made
fail-closed. `runtime-record-projections.mjs` no longer exports
`runtimeBridgeRunRecord()`, `runtimeBridgeMessagesForProjection()`, or
`runtimeBridgeComputerUseTrace()`, and `runtime-event-envelopes.mjs` no longer
derives action-proposal or commit-gate events from bridge readback. The daemon
index no longer wires these helpers into the runtime bridge turn path; Slice
1094 then deletes the remaining JS bridge-thread facade rather than preserving
it as a fail-closed wrapper.

Conformance now proves these projection builders and derived-event injector
stay absent instead of merely proving their output uses canonical field names.
Future positive runtime-service replay must be emitted by direct Rust
daemon-core projection over Agentgres-admitted truth, not by resurrected JS
bridge event shaping.

Slice 1251 hard-retires the remaining RuntimeAgentService bridge substrate.
`RuntimeApiBridge` no longer exports an adapter class/factory, the
`ioi-runtime-bridge` binary and Cargo bin entry are deleted, the daemon and
service reject `runtimeBridge` options, Rust service policy no longer reads
bridge allow-command envs, Autopilot uses an inference/model-route helper
instead of a bridge helper, and bridge-backed live proof scripts/tests are
removed. Conformance now fails if the JS adapter export, bridge helper,
command/env fallback, Cargo bridge binary, or runtimeBridge service option
returns.
Slice 1272 deletes the bridge-named JS helper file that still carried runtime
profile normalization: `runtime-api-bridge.mjs` and its test are absent, live
imports use `runtime-profile.mjs`, and conformance guards the old path as a
retired compatibility shim.

Slice 1094 retires the standalone runtime bridge thread/turn/control JS facade
module instead of preserving it as a fail-closed compatibility wrapper.
`packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs` and its focused
test are deleted, and the daemon store no longer imports or exposes
`createRuntimeBridgeThread()` or `createRuntimeBridgeTurn()` pass-through
methods. Runtime-service thread start, control, and turn submit now enter
positive Rust state-planning boundaries through direct lifecycle APIs; the
thread-turn surface delegates runtime resume to that Rust-owned lifecycle
boundary instead of preserving a JS bridge-control path.

Conformance now treats the deleted module as the invariant. Positive
runtime-service start, control, and turn submit arrived through Rust planning
plus Agentgres commit without recreating a Node bridge-thread facade. Remaining
runtime-service work must continue through direct Rust daemon-core admission,
execution dispatch, Agentgres expected-head/state-root binding, replay, and
projection paths.

Slice 1095 retires the dead computer-use JS invocation bodies that remained
behind the fail-closed facade guards. Browser discovery, control,
native-browser action, visual GUI action, sandboxed-hosted action, and visual
GUI observe now return the Rust-core-required boundary directly. The daemon
index no longer imports or calls local browser discovery, CDP execution,
controlled native-browser launch, visual GUI local capture/execution, or
computer-use request metadata helper plumbing from those invocation surfaces.
Visual GUI observe is also guard-only, so it cannot read local capture files or
look up JS truth before refusing the retired path.

Conformance now treats the absence of those JS invocation bodies as the
invariant. The bridge tier no longer expects canonical snake_case payload,
request, workflow-binding, selector, sandbox, controlled-relaunch, or visual
metadata construction inside daemon `index.mjs`; those shapes may only survive
in non-authoritative helper/replay contracts until direct Rust daemon-core
computer-use admission, wallet.network authority, cTEE custody policy where
applicable, Agentgres expected-head/state-root binding, event materialization,
replay, and projection own the positive path.

A later public computer-use request-lease cut supersedes that guard-only public
facade. Browser discovery, control, native-browser, visual GUI,
sandboxed-hosted, and visual GUI observe daemon methods now map their public
tool identity to canonical `computer_use.request_lease` input and invoke the
Rust-live coding-tool StepModule path. Rust `coding_tool_computer_use.rs` owns
lease request construction, provider registry selection, wallet.network
authority boundaries, provider-unavailable fail-closed semantics, receipt refs,
and canonical result fields. The JS edge remains only a narrow protocol
adapter; it still must not restore local browser discovery sync, CDP execution,
controlled native-browser launch, visual GUI capture/execution, local sandbox
execution, JS event projection construction, runtime-event append, or direct
computer-use event admission. Concrete provider execution, direct Rust
computer-use event materialization, cTEE custody, durable Agentgres
expected-head/state-root binding, replay, projection, and stable IDE/CLI/SDK
APIs remain non-terminal.

Slice 1096 retires the unused approval decision JS readback facade. The mounted
approval control surface no longer exports `latestApprovalDecisionEvent()`, and
the daemon store no longer exposes a pass-through method for approval decision
event lookup. Approval request, decision, and revoke routes already fail closed
at the mounted approval surface; this slice removes the stale duplicate
decision-readback shape so approval decision truth cannot be reintroduced as a
daemon-local event scan while Rust daemon-core authority admission, Agentgres
expected-head/state-root binding, wallet.network approval grants, receipt
materialization, replay, and projection remain the target owner.

Conformance now fails if the approval decision readback facade returns on the
approval surface or daemon store. At this point the remaining approval-request
event readback was explicitly limited to the current coding-tool
approval-satisfaction helper until that helper received a direct Rust
daemon-core replacement; Slice 1208 later retires that JS satisfaction gate
rather than preserving it as readback scaffolding.

Slice 1097 retires the coding-tool budget blocked-event JS projection facade.
`RuntimeCodingToolBudgetRecoverySurface` no longer exports
`latestCodingToolBudgetBlockedEventForRun()`, and the daemon store no longer
exposes the matching pass-through wrapper. The live run-level budget recovery
route still calls the mounted `codingToolBudgetRecoveryForRun()` control
surface, which fails closed through Rust-authored admission-required planning;
the deleted blocked-event projection was only stale readback scaffolding.

Conformance now fails if the blocked-event projection facade returns on the
budget-recovery surface or daemon store. Future budget-recovery blocked-event
projection must be authored by Rust daemon-core projection over Agentgres
admitted truth, not by reintroducing daemon-local event scans or JS projection
helpers.

Slice 1098 retires the remaining unused daemon-store thread auxiliary and MCP
helper pass-through delegates. Public/thread routes already call the mounted
thread auxiliary and MCP catalog/control surfaces directly; the daemon store no
longer exposes `inspectManagedSessionsForThread()`,
`inspectWorkspaceChangeReviewsForThread()`, `controlWorkspaceChangeForThread()`,
`controlManagedSessionForThread()`, `forkThread()`, `cancelRun()`,
`applyThreadMcpServerMutation()`, `mcpStatusWithLiveDiscovery()`,
`appendThreadMcpControlEvent()`, or `mcpServersForContext()` as compatibility
entrypoints.

Conformance now fails if those store-level delegates return. Thread auxiliary
and MCP route behavior must stay mounted-surface/protocol-edge only until Rust
daemon-core thread lifecycle, MCP authority/admission, Agentgres
expected-head/state-root binding, replay, and projection own the direct APIs;
future direct Rust APIs should replace the mounted JS surfaces rather than
reviving daemon-store wrapper methods.

The subsequent thread-fork cut moves the mounted fork path from fail-closed
scaffolding to Rust daemon-core `plan_runtime_thread_fork_control`: JS now only
forwards canonical source facts, commits the Rust-authored forked agent, admits
the Rust-authored `thread.forked` event, and validates the Rust projection.

Slice 1099 retires the daemon-store coding-tool artifact/governance,
workspace-snapshot/restore, and diagnostics-feedback helper pass-through
delegates. The coding-tool invocation surface now calls mounted
`codingToolGovernanceSurface`, `codingToolArtifactSurface`,
`workspaceSnapshotSurface`, and `diagnosticsFeedbackSurface` methods directly
instead of re-entering `AgentgresRuntimeStateStore` wrappers for approval
satisfaction/blocking, budget blocking, artifact reads/retrieval, command-stream
events, artifact draft materialization, patch snapshots, snapshot events, and
post-edit diagnostics.

The daemon store no longer exposes the retired helper entrypoints, including
`appendCodingToolCommandStreamEvents()`, `codingToolApprovalSatisfaction()`,
`blockCodingToolForApproval()`, `blockCodingToolForBudget()`,
`prepareWorkspaceSnapshotForPatch()`, `materializeWorkspaceSnapshotArtifact()`,
`appendWorkspaceSnapshotEvent()`, `workspaceSnapshotContentPackage()`,
`materializeWorkspaceRestorePreviewArtifact()`,
`materializeWorkspaceRestoreApplyArtifact()`,
`appendWorkspaceRestorePreviewEvent()`, `appendWorkspaceRestoreApplyEvent()`,
`maybeRunPostEditDiagnostics()`, `pendingDiagnosticsFeedbackForNextTurn()`,
`materializeCodingToolArtifactDrafts()`,
`materializeVisualGuiObservationArtifacts()`, `readCodingToolArtifact()`, and
`retrieveCodingToolResult()`. Conformance now fails if those wrappers return.
The remaining mounted JS surfaces are protocol-edge migration scaffolding until
direct Rust daemon-core coding-tool governance, artifact admission, snapshot
admission, diagnostics feedback projection, Agentgres expected-head/state-root
binding, replay, and projection APIs replace them.

Slice 1100 retires the daemon-store diagnostics-repair and conversation-artifact
helper pass-through delegates. Public/thread routes already call the mounted
diagnostics-repair and conversation-artifact surfaces directly; the daemon store
no longer exposes `executeDiagnosticsOperatorOverride()`,
`turnForOperatorOverrideEvent()`, `appendDiagnosticsOperatorOverrideEvent()`,
`createDiagnosticsRepairRetryTurn()`, `turnForRepairRetryEvent()`,
`appendDiagnosticsRepairRetryTurnEvent()`,
`resolveDiagnosticsRepairDecision()`,
`appendDiagnosticsRepairDecisionExecutedEvent()`,
`createConversationArtifact()`, `listConversationArtifacts()`,
`getConversationArtifact()`, `listConversationArtifactRevisions()`,
`performConversationArtifactAction()`, `exportConversationArtifact()`, or
`promoteConversationArtifact()` as compatibility entrypoints.

Conformance now fails if those store-level delegates return. The mounted JS
surfaces remain migration scaffolding only: conversation-artifact read projection
now has a Rust replay API over runtime `state_dir`, create/action/export/promote
control now has a positive Rust daemon-core API, and future direct positive APIs
must still retire the remaining temporary protocol-edge scaffolding with richer
Rust daemon-core diagnostics repair admission/projection,
ArtifactRef/PayloadRef admission, Agentgres expected-head and state-root
binding, receipt_binder, replay, and stable projection APIs.

Slice 1101 retires the unused workflow-edit target/context JS helper facades
instead of preserving them as fail-closed compatibility surface area. No live
route or caller uses `workflowEditThreadContext()` or
`resolveWorkflowEditTarget()`; the daemon store and mounted workflow-edit
surface no longer expose those methods, and conformance fails if their
`workflow_edit_thread_context` or `workflow_edit_target_resolution` JS facade
patterns return.

Workflow-edit proposal/apply remain the only mounted JS protocol-edge
operations for this lane until direct Rust daemon-core workflow-edit context,
target resolution, proposal admission, apply admission, wallet approval
authority, Agentgres expected-head/state-root binding, receipt binding, replay,
and projection APIs replace the temporary surface.

Slice 1102 retired the daemon-store workspace-trust warning pass-through
delegate. At that point the mounted thread-control surface kept
`appendWorkspaceTrustWarningEvent()` as a fail-closed migration surface, but the
daemon store no longer provided a duplicate `store.appendWorkspaceTrustWarningEvent()`
compatibility entrypoint, and conformance failed if that wrapper returned.

Slice 1105 moved workspace-trust warning and acknowledgement event ownership
into Rust daemon-core planning. The subsequent workspace-trust transport cut
routes that planner through typed
`daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate`, so JS sends
canonical request bodies without generic command `operation`/`backend`
envelopes and Rust rejects `plan_workspace_trust_control_state_update` as a
command operation. `plan_workspace_trust_control_state_update` authors warning
and acknowledgement event envelopes, receipt refs, policy refs, and
replay-bound acknowledgement payloads; the JS thread-control surface only
forwards canonical facts, requires the Rust planner before mode lookup/write,
and admits Rust-authored events through `admit_runtime_thread_event`. The old JS
repository-context warning record and acknowledgement payload construction stay
retired. Deeper wallet/cTEE workspace authority and stable direct projection
APIs remain terminal work beyond the temporary replay cache transport.

Slice 1103 splits the Rust StepModule bridge computer-use provider registry and
provider-selection helper out of `ioi_step_module_bridge/computer_use.rs` into
`ioi_step_module_bridge/computer_use_provider.rs`. The request-lease builder no
longer owns provider catalog records, provider hint matching, registry
projection, or fail-closed unavailable-provider selection.

This is bridge containment, not terminal architecture. The new provider module
is still temporary command-transport scaffolding for `computer_use.request_lease`
until direct Rust daemon-core computer-use admission, wallet.network authority,
cTEE/workspace custody, Agentgres expected-head/state-root binding,
receipt/event materialization, replay, and projection APIs replace the bridge.

Slice 1104 originally split the Rust model_mount accepted-receipt planning and invocation
receipt binding command boundary out of
`ioi_step_module_bridge/model_mount_command.rs` into
`ioi_step_module_bridge/model_mount_receipt_command.rs`. The general
model_mount command wrapper no longer owns `ReceiptBinder`,
`AgentgresAdmissionCore`, or `RustProjectionCore` imports, while the new receipt
boundary owns accepted-receipt head/transition planning, caller-supplied expected
head rejection, transition validation, StepModuleRouter admission, receipt
binding, accepted-receipt append, Agentgres admission, and projection binding.

That temporary command-transport receipt boundary is now superseded by the typed
Rust daemon-core model_mount receipt API: accepted-receipt head/transition
planning and invocation receipt binding call `daemonCoreModelMountApi` methods,
and Rust command-protocol source is deleted and conformance source-scans keep the old command operations absent before dispatch.

Slice 1105 splits the Rust coding-tool StepModule workload dispatch,
StepModuleRouter admission, receipt binding, Agentgres admission, and projection
binding path out of `ioi_step_module_bridge/coding_tool_command.rs` into
`ioi_step_module_bridge/coding_tool_receipt_command.rs`. The coding-tool command
wrapper now owns operation selection and workload observation shaping only; the
new receipt boundary owns `WorkloadClient::plan_step_module_dispatch`,
`StepModuleRouterCore`, `ReceiptBinder`, `AgentgresAdmissionCore`, and
`RustProjectionCore`.

This is still bridge containment, not terminal architecture. The receipt module
is temporary command-transport scaffolding until direct Rust daemon-core
coding-tool execution/admission APIs and Rust/WASM workload module execution
replace the Node bridge, JS StepModule command helper, JS command callers, and
remaining coding-tool JS protocol facades.

Slice 1106 splits receipt-bearing governed command execution out of
`ioi_step_module_bridge/governed_admission_command.rs` into
`ioi_step_module_bridge/governed_receipt_command.rs`. The governed-admission
wrapper now owns lighter L1 settlement and governed-improvement proposal
admission only; cTEE private workspace execution and worker/service package
invocation live in the governed receipt boundary, where accepted-receipt append
via `ReceiptBinder` remains explicit beside Rust cTEE/marketplace admission
records.

This is still bridge containment, not terminal architecture. The governed
receipt module is temporary command-transport scaffolding until direct Rust
daemon-core cTEE and worker/service package execution/admission APIs replace the
Node bridge, shared command runner, JS command callers, and remaining JS
protocol facades.

Slice 1107 moves durable Agentgres runtime-state persistence execution out of
`ioi_step_module_bridge/agentgres_command.rs` and into Rust
`AgentgresAdmissionCore`. The bridge no longer owns filesystem path
canonicalization, previous-transition lookup, projection-watermark derivation,
or admitted-record materialization writes for runtime state commits; it calls
Rust core `commit_runtime_run_state_to_dir` / persistence helpers and formats
the temporary command-transport response only.

This remains non-terminal because command transport and JS command callers still
exist, but the Agentgres durable-write side-effect boundary is now a Rust
daemon-core API instead of bridge-local persistence logic. Direct Rust
daemon-core Agentgres protocol APIs must still replace the Node bridge, shared
command runner, JS command callers, and remaining JS persistence facades.

Slice 1108 moves coding-tool subprocess and git command execution out of the
temporary StepModule bridge helper and into Rust
`coding_tool_execution.rs` under the kernel service crate. Bounded command
spawning, timeout enforcement, sanitized subprocess environment construction,
and read-only git execution are now Rust daemon-core service APIs; the bridge
helper delegates to them while keeping only workspace observation and
StepModule response shaping.

This is a larger Rust-core extraction cut, not terminal coding-tool migration.
The coding-tool bridge helper still owns path/observation helpers for now, and
the Node bridge, StepModule command runner, JS command callers, and remaining
coding-tool JS facades remain temporary scaffolding until direct Rust
daemon-core/workload APIs own coding-tool execution, admission, replay, and
stable protocol projection end to end.

Slice 1109 moves the coding-tool `file.apply_patch` workspace mutation path out
of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
patch edit validation, workspace path escape rejection, file read/write
execution, diff preview hashing, workspace snapshot draft construction, and
Agentgres-style operation/payload/head/state-root transition derivation for
patch mutations. The bridge helper delegates to Rust core and translates errors
only.

This remains non-terminal because the bridge still carries other coding-tool
workspace observation helpers and the JS invocation facade/StepModule command
transport still exist. The long-term target remains direct Rust
daemon-core/workload coding-tool execution and admission, with JS retained only
as stable protocol/API composition where needed.

Slice 1110 moves the coding-tool `file.inspect` workspace observation path out
of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
workspace path canonicalization, path escape rejection, metadata reads,
directory listing, file preview reads, preview line/byte bounding, and preview
hash derivation for `file.inspect`. The bridge helper delegates to Rust core
and translates errors only.

This remains non-terminal because the bridge still carries other coding-tool
workspace status, diff, test, and diagnostic observation helpers, and the JS
invocation facade/StepModule command transport still exist. The long-term
target remains direct Rust daemon-core/workload coding-tool execution and
admission, with bridge-local filesystem observation retired as each Rust-core
surface becomes verified.

Slice 1111 moves the coding-tool `workspace.status` and `git.diff` git-backed
workspace observation paths out of the temporary StepModule bridge helper and
into Rust `coding_tool_workspace.rs` under the kernel service crate. Rust core
now owns status command planning, diff command planning, workspace path
containment for diff targets, porcelain/diff output hashing, git-unavailable
response shaping, changed-file counting, diff preview truncation, and stat
projection for these observations. The bridge helper delegates to Rust core and
translates errors only.

This remains non-terminal because the bridge still carries `test.run` and
`lsp.diagnostics` helper plumbing, and the JS invocation facade/StepModule
command transport still exist. The long-term target remains direct Rust
daemon-core/workload coding-tool execution and admission, with bridge-local
workspace observation retired as each Rust-core surface becomes verified.

Slice 1112 moves the coding-tool `test.run` command execution observation path
out of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
test command allowlisting, command mapping for `node.test`, `npm.test`,
`cargo.test`, and `cargo.check`, cwd and path containment, sanitized test
environment filtering, timeout and output bounding, output hashing, pass/fail
status derivation, and response shaping. The bridge helper delegates to Rust
core and translates errors only.

This remains non-terminal because the bridge still carries `lsp.diagnostics`
helper plumbing, and the JS invocation facade/StepModule command transport
still exist. The long-term target remains direct Rust daemon-core/workload
coding-tool execution and admission, with bridge-local diagnostic/test
execution logic retired as each Rust-core surface becomes verified.

Slice 1113 moves the coding-tool `lsp.diagnostics` execution observation path
out of the temporary StepModule bridge helper and into Rust
`coding_tool_workspace.rs` under the kernel service crate. Rust core now owns
diagnostic command allowlisting, `auto` backend selection, node syntax-check
execution, TypeScript project/file check execution, local `tsc` discovery,
diagnostic project-context projection, TypeScript diagnostic parsing, node
diagnostic parsing, cwd/path containment, timeout and output bounding, output
hashing, diagnostic status derivation, and response shaping. The bridge helper
delegates to Rust core and translates errors only.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and coding-tool JS protocol facades still exist.
The long-term target remains direct Rust daemon-core/workload coding-tool
execution and admission, with the now-thin bridge helper retired when direct
Rust daemon-core/workload APIs own execution, admission, replay, projection, and
stable protocol APIs end to end.

Slice 1114 moves the coding-tool artifact data-plane normalization path for
`artifact.read` and `tool.retrieve_result` out of the temporary StepModule
bridge and into Rust `coding_tool_artifact.rs` under the kernel service crate.
Rust core now owns canonical `rust_workload_data_plane` envelope validation,
data-plane schema/source/operation checks, artifact-store result object
validation, content-hash recomputation, shell-fallback suppression, canonical
artifact/receipt ref extraction, evidence-ref derivation, and retirement of
old camelCase result aliases before the bridge formats the StepModule response.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and coding-tool JS protocol facades still exist.
The temporary bridge now delegates artifact/read retrieval normalization to
Rust core and rejects retired data-plane aliases; the long-term target remains
direct Rust daemon-core/workload coding-tool execution, admission, replay,
projection, artifact/event admission, and stable protocol APIs end to end.

Slice 1115 moves the coding-tool `computer_use.request_lease` planning path
out of the temporary StepModule bridge and into Rust
`coding_tool_computer_use.rs` under the kernel service crate. Rust core now
owns prompt/lane/session/action canonicalization, wallet.network authority
scope derivation, approval-required calculation, provider registry records,
provider hint matching, fail-closed unavailable-provider projection, request
seed hashing, receipt/evidence ref derivation, thread-tool input shaping, and
retired camelCase alias rejection/ignoring for request-lease inputs and output.

This remains non-terminal because the Node bridge, shared StepModule command
runner, JS command callers, and computer-use JS protocol facades still exist.
The deleted `ioi_step_module_bridge/computer_use_provider.rs` file is not a
long-term architecture target; the remaining bridge file delegates to Rust core
only, and the long-term target remains direct Rust daemon-core computer-use
admission, wallet.network/cTEE custody enforcement where applicable,
Agentgres-backed receipt/state-root binding, replay, projection, and stable
protocol APIs end to end.

Slice 1116 moves coding-tool StepModule result construction, workload dispatch
planning, StepModuleRouter admission, receipt binding, Agentgres admission,
projection binding, and response assembly out of the temporary Node receipt
bridge and into Rust `coding_tool_step_module.rs` under the kernel service
crate. Rust core now owns backend-to-projection status selection, successful
StepModule result shaping, workload-client dispatch request derivation,
dispatch evidence merging, result validation, router admission, receipt/state
binding, optional Agentgres operation admission, projection record creation,
and the canonical `rust_workload_command` response envelope for coding-tool
StepModule work.

This remains non-terminal because the Node bridge, command dispatch table,
shared StepModule command runner, JS command callers, and coding-tool JS
protocol facades still exist. The remaining
`ioi_step_module_bridge/coding_tool_receipt_command.rs` file is a temporary
delegate to Rust core, not a durable architectural boundary. The long-term
target remains direct Rust daemon-core/workload coding-tool execution,
admission, replay, projection, and stable protocol APIs end to end, with the
bridge deleted or reduced to external protocol transport once the direct Rust
daemon-core surface is verified.

Slice 1117 moved model_mount accepted-receipt response shaping and invocation
receipt binding/admission out of the temporary Node receipt bridge and into
Rust `model_mount_receipt.rs` under the kernel service crate. Rust core now
owns accepted-receipt head/transition direct API envelopes, model_mount
StepModule invocation/result gate checks, caller-supplied expected-head
rejection, Rust-planned accepted-receipt transition validation, transition
mismatch fail-closed checks, StepModuleRouter admission, receipt binding,
accepted-receipt append through `ReceiptBinder`, optional Agentgres operation
admission, projection record creation, and the canonical
`rust_daemon_core.model_mount.invocation_receipt_binding` response source.

The original receipt command-transport delegate is retired for this family:
`plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt` are no longer daemon-core command
operations. The remaining non-terminal work is the rest of model_mount transport
and stable protocol/API ownership, not accepted-receipt or invocation receipt
binding.

Slice 1118 moves governed receipt command response shaping for cTEE private
workspace execution and worker/service package invocation out of the temporary
Node receipt bridge and into Rust `governed_receipt.rs` under the kernel
service crate. Rust core now owns the governed receipt bridge request structs,
cTEE StepModule kind/backend guard, caller-supplied expected-head rejection,
private-workspace cTEE execution/admission wrapping, worker/service package
invocation admission wrapping, accepted-receipt append through `ReceiptBinder`,
and the canonical `rust_ctee_private_workspace_protocol` and
`rust_worker_service_package_invocation_protocol` response envelopes.

This was non-terminal because the Node bridge, command dispatch table, shared
daemon-core command runner, JS command callers, and receipt-bearing JS runners
still existed at that cut. Subsequent cTEE and worker/service package macro
cuts retired those JS runners. The remaining target is stable direct Rust
daemon-core cTEE and worker/service package protocol APIs over Agentgres-backed
receipt/state-root binding, replay, projection, wallet.network authority, cTEE
custody, and stable IDE/CLI/SDK surfaces end to end.

Slice 1119 moves Agentgres storage-write admission and runtime-state commit
command response shaping out of the temporary Node Agentgres command bridge and
into Rust `agentgres_command.rs` under the kernel service crate. Rust core now
owns the Agentgres command bridge request structs, storage-write admission
response envelope, runtime run-state persisted commit response envelope,
agent/memory/subagent/artifact/model-mount record/model-mount receipt state
commit response envelopes, and the per-record persistence helper that writes
through `AgentgresAdmissionCore` after storage admission.

This was non-terminal at that cut because the Node bridge, command dispatch
table, shared daemon-core command runner, JS command callers, runtime Agentgres
runner, and JS persistence callers still existed. The runtime Agentgres runner
and shared-command-helper path are now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut; the remaining target is direct Rust
daemon-core Agentgres protocol APIs over admitted receipt/state-root truth,
replay, projection, wallet.network authority where applicable, cTEE custody
where applicable, and stable IDE/CLI/SDK surfaces end to end.

Slice 1120 moves L1 settlement and governed runtime-improvement command
response shaping out of the temporary Node governed-admission command bridge
and into Rust `governed_admission.rs` under the kernel service crate. Rust core
now owns the governed admission protocol request structs, L1 trigger-guard
wrapping, governed-evolution proposal admission wrapping, canonical
`rust_l1_settlement_guard_protocol` and
`rust_governed_meta_improvement_protocol` response envelopes, and the error
codes returned to the bridge boundary.

This was non-terminal because the Node bridge, command dispatch table, shared
daemon-core command runner, JS command callers, L1 settlement runner, and
governed-improvement runner still existed at that cut. The L1 runner has now
been retired behind mounted `l1SettlementCore`, and governed-improvement has
now been retired behind mounted `governedImprovementCore`. The long-term target
remains direct Rust daemon-core governed-admission protocol APIs over settlement
trigger guards, governed proposal admission, Agentgres-backed
receipt/state-root truth where
applicable, replay, projection, wallet.network authority where applicable, and
stable IDE/CLI/SDK surfaces end to end.

Slice 1121 moved external capability exit authority response shaping out of the
temporary Node authority command bridge and into Rust `authority.rs` under the
kernel service crate. That path is now superseded by the direct authority API
cut: Rust core owns the protocol request struct, wallet.network authority
wrapping, canonical `rust_external_capability_exit_authority_protocol` response
envelope, authority grant/receipt/hash projection fields, and protocol-facing
error code for rejected external exits.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command caller, and external capability
authority runner still exist. The remaining
`ioi_step_module_bridge/authority_command.rs` file is a temporary delegate to
Rust core, not a durable wallet.network authority boundary. The long-term
target remains direct Rust daemon-core authority protocol APIs over
wallet.network grants, authority receipts, Agentgres-backed receipt/state-root
truth where applicable, replay, projection, and stable IDE/CLI/SDK surfaces end
to end.

Slice 1122 moves coding-tool approval manifest and approval
request/decision/revoke state-update command request/response shaping out of
the temporary Node approval command bridge and into Rust `approval.rs` under
the kernel service crate. Rust core now owns the bridge request structs,
approval manifest wrapping, approval state-update response envelopes,
canonical `rust_coding_tool_approval_command`,
`rust_approval_request_state_update_command`,
`rust_approval_decision_state_update_command`, and
`rust_approval_revoke_state_update_command` source markers, and bridge-facing
error codes for rejected approval command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, approval runners, and
approval surfaces still exist. The remaining
`ioi_step_module_bridge/approval_command.rs` file is a temporary delegate to
Rust core, not a durable approval authority or state-update boundary. The
long-term target remains direct Rust daemon-core approval protocol APIs over
wallet.network grants, Agentgres-backed expected-head/state-root truth,
receipt/event materialization, replay, projection, cTEE custody policy where
relevant, and stable IDE/CLI/SDK surfaces end to end.

Slice 1123 moves workflow-edit and diagnostics-repair admission-required
command request/response shaping out of the temporary Node policy command
bridge files and into Rust `policy/admission_required.rs`. Its
projection-required portion for public skill/hook registry, repository
workflow, runtime tool catalog, and runtime lifecycle routes is superseded by
positive Rust projection APIs, so those public route families no longer retain a
projection-required command owner.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, policy/projection
runners, and public fail-closed surfaces still exist. The remaining
`ioi_step_module_bridge/policy_command.rs` and
`ioi_step_module_bridge/projection_command.rs` files are temporary delegates
to Rust core, not durable admission or projection boundaries. The long-term
target remains direct Rust daemon-core admission/projection protocol APIs over
wallet.network authority where applicable, Agentgres-backed expected-head and
state-root truth, receipt/event materialization, replay, projection, and stable
IDE/CLI/SDK surfaces end to end.

Slice 1124 moves context budget, coding-tool budget, compaction policy,
context-compaction plan, and context-compaction state-update command
request/response shaping out of the temporary Node context-policy bridge and
into Rust `policy/context_lifecycle.rs`. Rust core now owns the bridge request
structs, response envelopes, canonical command source markers, and
bridge-facing error codes for rejected context lifecycle command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, and context-policy
runners still exist. Public `compactThread()` now consumes the Rust
context-compaction plan and state-update plan through Rust Agentgres
runtime-event admission and Agentgres-backed run/agent persistence; public
thread/run context-budget and thread compaction-policy routes now require Rust
policy planning plus Rust Agentgres runtime-event admission before returning
route truth, with compaction-policy execution composed through the Rust-owned
`compactThread()` path when Rust approves compaction. The remaining
`ioi_step_module_bridge/context_policy_command.rs` file is a temporary delegate
to Rust core, not a durable context policy boundary. The long-term target
remains direct Rust daemon-core context admission/projection protocol APIs over
Agentgres expected-head and state-root truth, policy receipts, context
compaction event materialization, replay, projection, and stable IDE/CLI/SDK
surfaces end to end.

Slice 1125 moves workspace-restore apply-policy, preview/apply operations, and
workspace-snapshot capture command request/response shaping out of the
temporary Node workspace-restore bridge and into Rust `workspace_restore.rs`.
Rust core now owns the bridge request structs, response envelopes, canonical
command source markers, and bridge-facing error codes for rejected
workspace-restore command bodies.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, workspace-restore
runner, and public fail-closed workspace snapshot/restore surfaces still
exist. The remaining `ioi_step_module_bridge/workspace_restore_command.rs`
file is a temporary delegate to Rust core, not a durable workspace
snapshot/restore boundary. The long-term target remains direct Rust
daemon-core workspace snapshot/restore admission, policy/approval,
filesystem-operation, artifact/payload admission, Agentgres expected-head and
state-root truth, receipts/events, replay, projection, and stable IDE/CLI/SDK
surfaces end to end.

Slice 1126 moves thread lifecycle command request/response shaping out of the
temporary Node thread-lifecycle bridge and into Rust
`policy/thread_lifecycle.rs`. Rust core now owns the bridge request structs,
response envelopes, canonical command source markers, bridge-facing error
codes, and policy facade exports for runtime bridge thread-start state updates,
runtime bridge turn-run state updates, subagent record updates, thread-control
agent updates, thread-turn admission-required refusals, lifecycle
admission-required refusals, agent-create updates, agent-status updates, and
run-create updates.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, and public thread/agent/run/subagent lifecycle surfaces still exist.
At this slice, the remaining `ioi_step_module_bridge/thread_lifecycle_command.rs`
file was a temporary delegate to Rust core, not a durable lifecycle boundary;
Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core thread, turn, agent, run, subagent, and lifecycle
admission/persistence APIs over Agentgres expected-head and state-root truth,
wallet.network authority where applicable, receipt/event materialization,
replay, projection, and stable IDE/CLI/SDK surfaces end to end.

Slice 1127 moves MCP/memory command request/response shaping out of the
temporary Node MCP/memory bridge and into Rust `policy/mcp_memory.rs`. Rust
core now owns the bridge request structs, response envelopes, canonical command
source markers, bridge-facing error codes, and policy facade exports for MCP
control agent updates, MCP server validation, MCP validation-input projection,
MCP manager status/catalog/catalog-summary/validation projection, memory
manager status/validation projection, and thread-memory agent updates.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, MCP catalog/control surfaces, and thread-memory surfaces still exist.
At this slice, the remaining `ioi_step_module_bridge/mcp_memory_command.rs`
file was a temporary delegate to Rust core, not a durable MCP or memory
boundary; Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core MCP and memory admission/projection APIs over wallet.network
authority for external exits, Agentgres expected-head and state-root truth,
receipt/event materialization, transport containment, replay, projection, and
stable IDE/CLI/SDK surfaces end to end.

Slice 1128 moves runtime-control command request/response shaping out of the
temporary Node runtime-control bridge and into the Rust policy owner modules:
`policy/coding_tool_budget_recovery.rs`, `policy/operator_control.rs`, and
`policy/run_cancel.rs`. Rust core now owns the bridge request structs, response
envelopes, canonical command source markers, and bridge-facing error codes for
coding-tool budget recovery state updates and admission-required refusals,
diagnostics operator override state updates, operator turn-control
admission-required refusals, operator interrupt/steer state updates, and
run-cancel state updates and admission-required refusals.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime context-policy
runner, diagnostics repair surface, operator turn-control surface,
coding-tool budget recovery surface, and run-cancel surface still exist. At
this slice, the remaining `ioi_step_module_bridge/runtime_control_command.rs`
file was a temporary delegate to Rust core, not a durable runtime-control
boundary; Slice 1139 later deleted it. The long-term target remains direct Rust
daemon-core runtime-control admission/persistence/projection APIs over
wallet.network authority where approval or operator authority applies,
Agentgres expected-head and state-root truth, receipt/event materialization,
replay, projection, and stable IDE/CLI/SDK surfaces end to end.

Slice 1129 originally moved model-mount read-projection request/response
shaping out of the temporary Node model-mount bridge and into Rust
`model_mount/read_projection.rs`. The current read-projection typed API cut
supersedes that command-envelope shape: Rust daemon-core now exposes
`RuntimeKernelService::plan_model_mount_read_projection`, and the JS
`ModelMountCore` calls it through
`daemonCoreModelMountApi.planModelMountReadProjection` without a command
operation, backend marker, or bridge response wrapper.

This remains non-terminal because the broader Node model-mount bridge, command
dispatch table, shared daemon-core command runner, JS command callers,
model-mount core, and JS state-materialization/read-projection
facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable model-mount projection boundary; Slice 1140 later
retires that child delegate. The long-term target remains direct Rust
daemon-core model-mount
projection APIs over Agentgres expected-head and state-root truth,
receipt-bound topology, wallet.network/cTEE authority where applicable,
replay, projection, and stable IDE/CLI/SDK surfaces end to end.

Slice 1130 moves model-mount backend-process and required-control command
request/response shaping out of the temporary Node model-mount bridge and into
Rust `model_mount/backend_process.rs` plus `model_mount/required.rs`. Rust core
now owns the bridge request structs, response envelopes, canonical command
source markers, backend defaults, and bridge-facing error propagation for
`plan_model_mount_backend_process`,
`plan_model_mount_backend_lifecycle_required`,
`plan_model_mount_tokenizer_required`, and
`plan_model_mount_route_control_required`; the remaining Node functions only
delegate to the Rust response functions. The server-control required command
was later retired when the positive `plan_model_mount_server_control` boundary
became the canonical server-control path, and the runtime-engine required
command was later retired when the positive
`plan_model_mount_runtime_engine` boundary became the canonical runtime-engine
control path. The backend-lifecycle required command was later retired when the
positive `plan_model_mount_backend_lifecycle` boundary became the canonical
public backend health/start/stop/log path. Slice 1220 later retires tokenizer
and route-control required command transport in favor of typed
`daemonCoreModelMountApi.planModelMountTokenizerRequired`,
`daemonCoreModelMountApi.planModelMountRouteControlRequired`, and
`daemonCoreModelMountApi.planModelMountTokenizer`.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers, local
model-mount materialization, provider/lifecycle wrapper delegates, and mounted
JS facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable backend-process or required-control boundary; Slice
1140 later retires that child delegate. The long-term target remains direct Rust daemon-core
model-mount control/projection APIs over Agentgres expected-head and state-root
truth, receipt-bound topology, wallet.network/cTEE authority where applicable,
replay, projection, and stable IDE/CLI/SDK surfaces end to end.

Slice 1131 moves model-mount provider lifecycle, provider inventory, and
instance lifecycle command request/response shaping out of the temporary Node
model-mount bridge and into Rust `model_mount/lifecycle.rs`. Rust core now owns
the bridge request structs, response envelopes, canonical command source
markers, backend defaults, and bridge-facing error propagation for
`plan_model_mount_provider_lifecycle`, `plan_model_mount_provider_inventory`,
and `plan_model_mount_instance_lifecycle`; the remaining Node functions only
delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers, local
model-mount materialization, provider execution/provider-result wrapper
delegates, and mounted JS facades still exist. At this slice, the remaining
`ioi_step_module_bridge/model_mount_command.rs` file was temporary transport
scaffolding, not a durable provider lifecycle, provider inventory, or instance
lifecycle boundary; Slice 1140 later retires that child delegate. The long-term target remains direct Rust daemon-core
model-mount lifecycle/projection APIs over Agentgres expected-head and
state-root truth, receipt-bound topology, wallet.network/cTEE authority where
applicable, replay, projection, and stable IDE/CLI/SDK surfaces end to end.

Slice 1132 moves model-mount route-decision and invocation-admission command
request/response shaping out of the temporary Node model-mount bridge and into
Rust `model_mount/admission.rs`. Rust core now owns the bridge request structs,
response envelopes, canonical command source markers, backend defaults, and
bridge-facing error propagation for `admit_model_mount_route_decision` and
`admit_model_mount_invocation`. The Rust admission owner also authors the
accepted `model_route_selection` receipt detail envelope, including canonical
snake_case route/model/provider/workflow fields and the
`rust_daemon_core_model_route_selection_receipt` evidence marker. The remaining
Node functions only delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers,
model-mount core, provider execution/provider-result wrapper
delegates, local materialization, and mounted JS facades still exist. At this
slice, the remaining `ioi_step_module_bridge/model_mount_command.rs` file was
temporary transport scaffolding, not a durable model-mount admission boundary;
Slice 1140 later retires that child delegate. The long-term target remains
direct Rust daemon-core model-mount admission,
provider execution, receipt/state-root binding, Agentgres truth, wallet.network
and cTEE authority checks where applicable, replay, projection, and stable
IDE/CLI/SDK surfaces end to end.

Slice 1133 moves the remaining model-mount provider command response shaping
out of the temporary Node model-mount bridge and into Rust
`model_mount/provider_execution.rs` plus `model_mount/provider_result.rs`.
Rust core now owns the bridge request structs, response envelopes, canonical
command source markers, backend defaults, provider invocation alias fields,
stream invocation alias fields, and bridge-facing error propagation for
`admit_model_mount_provider_execution`,
`execute_model_mount_provider_invocation`,
`execute_model_mount_provider_stream_invocation`, and
`admit_model_mount_provider_result`. The remaining Node functions only
delegate to the Rust response functions.

This remains non-terminal because model-mount command transport, command
dispatch, the shared daemon-core command runner, JS command callers,
model-mount core, local materialization, mounted JS facades, and
direct daemon-core protocol/API extraction still exist. At this slice, the
remaining `ioi_step_module_bridge/model_mount_command.rs` file was temporary
transport scaffolding, not a durable model-mount provider boundary; Slice 1140
later retires that child delegate. The long-term target remains direct Rust
daemon-core model-mount admission, provider execution,
provider-result admission, receipt/state-root binding, Agentgres truth,
wallet.network and cTEE authority checks where applicable, replay, projection,
and stable IDE/CLI/SDK surfaces end to end.

Slice 1134 moves coding-tool StepModule command request/response shaping out
of the temporary Node coding-tool bridge and into Rust
`coding_tool_step_module.rs`. Rust core now owns the bridge request struct,
command validation, per-tool dispatch, workload observation envelopes,
StepModule result construction, receipt binding, Agentgres admission,
projection records, artifact data-plane binding, and computer-use lease
receipt/evidence binding for the Rust-live coding-tool set. The remaining
`ioi_step_module_bridge/coding_tool_command.rs` file only delegates to Rust
response functions, while the dead `coding_tool_receipt_command.rs` and
`computer_use.rs` bridge shims are deleted.

This remains non-terminal because StepModule command transport, command
dispatch, JS command callers, runtime coding-tool invocation facades, and
direct daemon-core/workload protocol/API extraction still exist. The remaining
coding-tool Node bridge files are temporary transport/test scaffolding, not a
durable coding-tool execution boundary. The long-term target remains direct
Rust daemon-core and Rust/WASM coding-tool admission, execution,
receipt/state-root binding, Agentgres truth, wallet.network and cTEE authority
checks where applicable, replay, projection, and stable IDE/CLI/SDK surfaces
end to end.

Slice 1135 retires the now-empty coding-tool StepModule command wrapper module
instead of preserving it as a compatibility shim. The temporary bridge no
longer declares `ioi_step_module_bridge/coding_tool_command.rs`; that file is
deleted, and the bridge module imports the Rust
`coding_tool_step_module.rs` response functions directly for the remaining
stdin/JSON dispatch and proof-test transport. Command identity and schema
validation moved through Rust command-protocol ownership and now resolve to
source-absence conformance, while coding-tool
request/response shaping, StepModuleRouter admission, workload dispatch,
receipt/state-root binding, Agentgres admission, projection, artifact
data-plane binding, and computer-use lease evidence binding remain Rust
`coding_tool_step_module.rs` ownership.

This remains non-terminal because the shared command dispatch table,
StepModule command runner, JS command callers, runtime coding-tool invocation
facades, and direct daemon-core/workload protocol/API extraction still exist.
The surviving `ioi_step_module_bridge` coding-tool imports are temporary
transport/test scaffolding, not a durable coding-tool execution boundary. The
next larger cut should replace the remaining command transport and JS caller
path with direct Rust daemon-core and Rust/WASM workload APIs once that seam is
clear enough to remove without preserving compatibility behavior.

Slice 1136 moves the remaining temporary command-operation dispatch table out
of the Node bridge and into Rust kernel code. The deleted
`ioi_step_module_bridge/command_dispatch.rs` file is replaced by
`crates/services/src/agentic/runtime/kernel/command_dispatch.rs`, where Rust
core now owns typed `CommandOperation` dispatch, request decoding, response
selection, and bridge-facing error mapping for the current StepModule and
daemon-core command surfaces. The Node `bridge_dispatch.rs` module now only
reads stdin JSON, validates the canonical Rust `CommandEnvelope`, and calls
Rust `dispatch_command_operation_response()`.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and several
proof-test delegate modules still exist as migration scaffolding. The deleted
Node dispatch table must not be recreated or treated as canonical; the next
larger cuts should retire the shared JS command runner/caller path and replace
the remaining bridge transport with direct Rust daemon-core and Rust/WASM
workload protocol APIs once the seam is clear enough to remove without
preserving compatibility behavior.

Slice 1137 retires five now-redundant bridge child wrapper modules instead of
preserving them as compatibility shims. The deleted files are
`ioi_step_module_bridge/approval_command.rs`,
`ioi_step_module_bridge/authority_command.rs`,
`ioi_step_module_bridge/governed_admission_command.rs`,
`ioi_step_module_bridge/governed_receipt_command.rs`, and
`ioi_step_module_bridge/workspace_restore_command.rs`. Their proof-test
surfaces now import Rust response functions and request types directly from
`approval.rs`, `authority.rs`, `governed_admission.rs`,
`governed_receipt.rs`, and `workspace_restore.rs`, while runtime command
dispatch remains Rust `command_dispatch.rs` ownership.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and remaining
bridge child delegates still exist as migration scaffolding. The deleted child
wrappers must not be recreated or treated as canonical. The next larger cuts
should continue collapsing remaining bridge delegates and then replace the JS
command-runner/caller path with direct Rust daemon-core and Rust/WASM workload
protocol APIs once the seam is clear enough to remove without preserving
compatibility behavior.

Slice 1138 retires four more bridge child wrapper modules that had become
pure Rust delegate shells. The deleted files are
`ioi_step_module_bridge/agentgres_command.rs`,
`ioi_step_module_bridge/context_policy_command.rs`,
`ioi_step_module_bridge/policy_command.rs`, and
`ioi_step_module_bridge/projection_command.rs`. The remaining bridge proof
surface imports Rust response functions and request types directly from
`agentgres_command.rs`, `policy/context_lifecycle.rs`,
`policy/admission_required.rs`, and the positive projection owner modules such
as `runtime_lifecycle.rs`; runtime operation dispatch remains Rust
`command_dispatch.rs` ownership.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, and remaining
bridge child delegates for runtime-control, thread lifecycle, MCP/memory, and
model-mount families still exist as migration scaffolding. The deleted child
wrappers must not be recreated or treated as canonical. The next larger cuts
should either retire the remaining child delegates the same way where they are
pure shells, or replace the JS command-runner/caller path with direct Rust
daemon-core and Rust/WASM workload protocol APIs once that seam is clear enough
to remove without preserving compatibility behavior.

Slice 1139 retires the runtime-control, thread-lifecycle, and MCP/memory
bridge child modules after runtime command dispatch had already moved into
Rust `command_dispatch.rs` and those files had become proof-only delegate
shells. The deleted files are
`ioi_step_module_bridge/runtime_control_command.rs`,
`ioi_step_module_bridge/thread_lifecycle_command.rs`, and
`ioi_step_module_bridge/mcp_memory_command.rs`. The bridge proof surface now
imports Rust response functions and request types directly from
`policy/coding_tool_budget_recovery.rs`, `policy/operator_control.rs`,
`policy/run_cancel.rs`, `policy/thread_lifecycle.rs`, and
`policy/mcp_memory.rs`.

This was non-terminal because the Node bridge binary, JS daemon-core command
runner, StepModule command runner, JS command callers, model-mount bridge
delegates, and broader JS facade/readback surfaces still existed as migration
scaffolding. Slice 1140 later retires the model-mount child delegates. The
deleted policy/lifecycle/MCP wrapper files must not be recreated or treated as
canonical, and the next larger cuts should replace the JS command-runner/caller
path and broad bridge transport with direct Rust daemon-core and Rust/WASM
workload protocol APIs once that seam is clear enough to remove without
preserving compatibility behavior.

Slice 1140 retires the final model-mount bridge child delegate modules after
runtime command dispatch had already moved into Rust `command_dispatch.rs` and
model-mount request/response ownership had moved into Rust
`model_mount.rs` and `model_mount_receipt.rs`. The deleted files are
`ioi_step_module_bridge/model_mount_command.rs` and
`ioi_step_module_bridge/model_mount_receipt_command.rs`. The bridge proof
surface now imports Rust model-mount admission, provider execution, lifecycle,
backend planning, accepted-receipt, and invocation-receipt binding response
functions and request types directly from the Rust kernel modules; current
read-projection ownership has since moved to the typed daemon-core model_mount
API.

This remains non-terminal because the Node bridge binary, JS daemon-core
command runner, StepModule command runner, JS command callers, model-mount
admission runner, local materialization, JS readback/protocol edge surfaces,
and broader facade/readback surfaces still exist as migration scaffolding. The
deleted model-mount child wrappers must not be recreated or treated as
canonical. The next larger cuts should replace the broad bridge transport and
JS command-runner/caller path with direct Rust daemon-core and Rust/WASM
workload protocol APIs once that seam is clear enough to remove without
preserving compatibility behavior.

Slice 1141 retires the remaining `coding_tool_helpers.rs` bridge helper after
coding-tool workspace execution semantics had already moved into Rust
`coding_tool_workspace.rs`, Rust execution semantics had moved into
`coding_tool_execution.rs`, and StepModule command dispatch had moved into
Rust `command_dispatch.rs`. The broad bridge proof surface now imports the
Rust workspace inspect/test/git/LSP helpers directly for proof tests instead
of routing through a sibling helper module.

This was non-terminal because the Node bridge binary, JS StepModule command
runner, JS daemon-core command runner, JS command callers, runtime coding-tool
facades, and broad bridge stdin/JSON transport still existed as migration
scaffolding. Slice 1142 later retires the dedicated StepModule command runner
wrapper. The deleted coding-tool helper must not be recreated or treated as
canonical.

Slice 1142 retired `packages/runtime-daemon/src/step-module-command-runner.mjs`
as a second JS command-wrapper shape. At that historical cut, the temporary
StepModule runner remained `rust_workload_live` by construction and called the
shared `runtime-daemon-core-command-runner.mjs` invoker with StepModule-specific
schema/error metadata instead of owning a distinct child-process wrapper. Later
slices delete that shared command runner, the bridge binary, and finally the
temporary StepModule runner facade itself; the live coding-tool path now calls
the typed Rust workload API directly from the invocation surface.

This remains non-terminal because the Node bridge binary, shared JS daemon-core
command runner, JS command callers, runtime coding-tool facades, and broad
bridge stdin/JSON transport still exist as migration scaffolding. The deleted
StepModule command runner wrapper must not be recreated or treated as
canonical. The next larger cuts should replace the remaining shared command
runner/caller path and broad bridge transport with direct Rust daemon-core and
Rust/WASM workload protocol APIs once that seam is clear enough to remove
without preserving compatibility behavior.

Slice 1143 moves L1 settlement product-route admission envelope authorship out
of the JS surface and into Rust `governed_admission.rs`. The Rust
`L1SettlementAdmissionProtocolRequest` now accepts thread/agent route context and
`admit_l1_settlement_attempt_protocol_response()` emits the canonical
`ioi.runtime.l1_settlement_admission.v1` route envelope, including
`settlement_admitted`, `thread_id`, `agent_id`, settlement refs, trigger refs,
receipt refs, Rust-derived state-root refs, and admission hash. The JS L1
settlement surface now only extracts the canonical `attempt` request body,
rejects retired request aliases and caller-supplied state-root truth, looks up
the thread agent, and forwards context to the mounted core; it no longer mints
the public settlement-admission response locally. The mounted core now requires
typed `daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt`, rejects generic
`daemonCoreInvoker`, and the old Rust `admit_l1_settlement_attempt` command
operation is retired.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side L1 response-envelope authorship must not be recreated or
treated as canonical. The next larger cuts should repeat this ownership move
for the remaining governed admission/product-route families where Rust already
has the response context, then replace the shared command runner/caller path
and broad bridge transport with direct Rust daemon-core protocol APIs.

Slice 1144 moves worker/service package product-route admission envelope
authorship out of the JS surface and into Rust `governed_receipt.rs`. The Rust
`WorkerServicePackageInvocationProtocolRequest` now accepts thread/agent route
context and `admit_worker_service_package_invocation_protocol_response()` emits
the canonical `ioi.runtime.worker_service_package_admission.v1` route envelope,
including `invocation_admitted`, `thread_id`, `agent_id`, package refs,
StepModuleRouter admission, receipt binding, accepted-receipt append,
Agentgres admission, projection record, receipt refs, artifact refs, payload
refs, and authority grant refs. The JS worker/service package surface now only
extracts the canonical `invocation` body, rejects retired request/truth fields,
looks up the thread agent, and forwards context to the mounted core; it no
longer mints the public package-admission response locally. The mounted core now
requires typed `daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation`,
rejects generic `daemonCoreInvoker`, and the old Rust
`admit_worker_service_package_invocation` command operation is retired.

This remains non-terminal because richer package projection/replay records,
Agentgres receipt/state-root binding, and stable IDE/CLI/SDK package admission
read APIs still need direct Rust ownership. The deleted JS-side worker/service
package response-envelope authorship and command-envelope operation must not be
recreated or treated as canonical. The next larger cuts should continue
removing JS product-route envelope authorship where Rust already owns the
admission/receipt context, then replace the shared command runner/caller path
and broad bridge transport with direct Rust daemon-core protocol APIs.

Slice 1145 moves cTEE Private Workspace product-route admission envelope
authorship out of the JS surface and into Rust `governed_receipt.rs`. The Rust
`CteePrivateWorkspaceProtocolRequest` accepts thread/agent route context and
`execute_private_workspace_ctee_action_protocol_response()` emits the canonical
`ioi.runtime.ctee_private_workspace_admission.v1` route envelope, including
`action_executed`, `thread_id`, `agent_id`, invocation/receipt refs, receipt,
result, receipt binding, accepted-receipt append, Agentgres admission,
projection record, receipt refs, and evidence refs. The JS cTEE surface now
only extracts the canonical `action` body, rejects retired request/truth
fields, looks up the thread agent, and forwards context to the Rust-backed
runner; it no longer mints the public cTEE admission response locally.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side cTEE response-envelope authorship must not be recreated or
treated as canonical. The next larger cuts should replace the shared command
runner/caller path and broad bridge transport with direct Rust daemon-core
protocol APIs once that seam is clear enough, then continue facade retirement
for the remaining JS product/readback surfaces.

Slice 1146 moves governed runtime-improvement product-route admission envelope
authorship out of the JS surface and into Rust `governed_admission.rs`. The
Rust `GovernedRuntimeImprovementProtocolRequest` now accepts thread/agent route
context and `admit_governed_runtime_improvement_proposal_protocol_response()` emits the
canonical `ioi.runtime.governed_improvement_admission.v1` route envelope,
including `proposal_admitted`, `mutation_executed`, `thread_id`, `agent_id`,
proposal refs, admission hash, Agentgres operation/state roots, resulting
head, approval ref, and rollback ref. The JS governed-improvement surface now
only extracts the canonical `proposal` body, rejects retired request/truth
fields, looks up the thread agent, and forwards context to the Rust-backed
core; it no longer mints the public governed-improvement admission response
locally. The mounted core now requires typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal`,
rejects generic `daemonCoreInvoker`, and the old Rust
`admit_governed_runtime_improvement_proposal` command operation is retired.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side governed-improvement response-envelope authorship must not be
recreated or treated as canonical. The next larger cuts should replace the
shared command runner/caller path and broad bridge transport with direct Rust
daemon-core protocol APIs once that seam is clear enough, then continue facade
retirement for the remaining JS product/readback surfaces.

Slice 1147 moves external capability exit authority product-route response
envelope authorship out of the JS surface and into Rust `authority.rs`. The
Rust `ExternalCapabilityExitAuthorityProtocolRequest` now accepts thread/agent
route context and `authorize_external_capability_exit_protocol_response()` emits
the canonical `ioi.runtime.external_capability_authority.v1` route envelope,
including `status`, `exit_authorized`, `direct_truth_write_allowed`,
`thread_id`, `agent_id`, authority refs, grant refs, receipt refs, and the
authority hash. The JS external-capability authority surface now only extracts
the canonical `request` body, rejects retired aliases, looks up the thread
agent, and forwards context to the mounted Rust core; it no longer mints the
public authority response locally.

This remains non-terminal because the route still reaches Rust through the
shared JS daemon-core command runner and Node bridge stdin/JSON transport. The
deleted JS-side external capability authority response-envelope authorship
must not be recreated or treated as canonical. The next larger cuts should
replace the shared command runner/caller path and broad bridge transport with
direct Rust daemon-core authority protocol APIs once that seam is clear enough,
then continue facade retirement for the remaining JS product/readback surfaces.

Slice 1148 removed the remaining JS-side defaulting for the external
capability authority product-route envelope from the daemon runner normalizer.
That direct-invoker-only migration edge is now superseded by the Slice 1205
core cut: `runtime-external-capability-authority-runner.mjs` is deleted,
`externalCapabilityAuthorityCore` is mounted on the daemon store, and external
capability authorization no longer has a runner normalizer, command/env
fallback, or JS response-envelope compatibility path.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry the request to Rust. The long-term target is
still direct Rust daemon-core authority protocol/API wiring, not preservation
of the current Node command path.

Slice 1149 retires JS-side public projection fallbacks from the MCP/memory
manager context-policy runner normalizers. Rust `policy/mcp_memory.rs` already
authors MCP manager status, MCP validation, MCP catalog, MCP catalog summary,
memory manager status, and memory validation projection response fields through
the daemon-core command path. The JS
`runtime-context-policy-core.mjs` now passes missing Rust-owned
`object`, `status`, count, readiness, route, and projection policy fields
through as `null` instead of reconstructing public projection truth from
arrays, booleans, or hard-coded defaults.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry those projection requests to Rust, and the
broader MCP/memory surfaces still need direct Rust daemon-core protocol APIs,
Agentgres-backed truth, replay, and stable IDE/CLI/SDK projection wiring. The
retired JS fallback projection behavior must not be recreated as a
compatibility shim.

Slice 1150 retires JS-side public context lifecycle fallbacks from the
context-policy runner normalizers. Rust `policy/context_lifecycle.rs` already
authors context-budget policy, compaction-policy, context-compaction plan, and
context-compaction state-update public record fields through the daemon-core
command path. The JS `runtime-context-policy-core.mjs` now passes missing
Rust-owned `object`, `status`, mode/action, event identity, payload schema,
compaction policy, boolean decision, and target fields through as `null`
instead of reconstructing plausible context lifecycle records from hard-coded
defaults or bridge transport metadata.

This remains non-terminal because the shared JS daemon-core command runner and
Node bridge transport still carry those context lifecycle requests to Rust, and
context policy still needs direct Rust daemon-core protocol APIs, durable
Agentgres expected-head/state-root persistence, richer policy receipts/events,
replay, projection, and stable IDE/CLI/SDK wiring. Public `compactThread()` is
now Rust-planned, admits the Rust-authored `context.compacted` event through
Rust Agentgres runtime-event admission, binds the state update to the admitted
event id/seq, and commits only the Rust-planned run/agent projection through
Agentgres-backed persistence. Public thread/run context-budget and thread
compaction-policy routes now validate Rust-authored policy-event identity and
admit the Rust-planned policy events before returning route truth; approved
compaction-policy execution composes through `compactThread()`. The retired JS
fallback context lifecycle behavior must not be recreated as a compatibility
shim.

Slice 1151 retires the remaining JS-side state-update envelope fallbacks from
the shared context-policy runner. Rust policy cores already author typed
state-update records for coding-tool budget recovery, diagnostics operator
override, operator interrupt/steer, run cancel, thread control, MCP control,
thread memory, runtime bridge thread start/control/turn submit, subagent record,
agent create/status, and run create paths. The JS
`runtime-context-policy-core.mjs` now passes missing Rust-owned `object` and
`status` fields through as `null` for those state-update normalizers instead
of synthesizing `status: "planned"` as compatibility truth.

This remains non-terminal because the JS context-policy runner and Node bridge
transport still carry the state-update requests to Rust. The target is direct
Rust daemon-core state-update/admission/projection APIs backed by Agentgres
expected-head/state-root persistence, receipts/events, replay, and stable
IDE/CLI/SDK protocol surfaces, not preservation of a JS normalizer as a
canonical state-update envelope author.

Slice 1152 retires JS-side fallback synthesis from the model_mount core
runner for Rust-authored receipt, evidence, process, inventory, accepted-head,
accepted-transition, receipt-binding, and read-projection result fields. Rust
`model_mount` already owns these response records behind the temporary
daemon-core command path, so `model-mount-core.mjs` now preserves
missing Rust-owned arrays, booleans, counts, and process args as `null` instead
of inventing empty refs, `false` supervision/spawn decisions, or inventory
counts from JS-local fallbacks.

This remains non-terminal because the JS model_mount core request builder, shared
daemon-core command runner, and Node bridge transport still carry requests to
Rust. The target is direct Rust daemon-core model_mount protocol/API ownership
over admission, receipt/state-root binding, Agentgres truth, projection,
replay, and stable IDE/CLI/SDK protocol surfaces, not preservation of JS
normalizers as compatibility shims.

Slice 1153 first retired JS-side receipt/evidence ref fallback synthesis from
the cTEE Private Workspace migration edge. That runner has since been removed:
the daemon now mounts `cteePrivateWorkspaceCore`, requires typed
`daemonCoreCteeApi.executePrivateWorkspaceCteeAction`, rejects the retired
generic `daemonCoreInvoker` command-transport option, and returns the Rust
`governed_receipt.rs` cTEE custody protocol envelope as-is instead of inventing
receipt/evidence refs, source, or backend compatibility truth. The deleted command-protocol source plus conformance source scans keep the old
`execute_private_workspace_ctee_action` operation absent, so this migrated custody path cannot return through the temporary
command dispatcher.

This remains non-terminal because richer cTEE projection/replay records,
Agentgres receipt/state-root binding, and stable IDE/CLI/SDK cTEE read APIs
still need direct Rust ownership, and other route families still carry
temporary command transport.

Slice 1154 retired JS-side ref fallback synthesis from the temporary
worker/service package runner. Rust `governed_receipt.rs` already owned the
receipt-bearing worker/service package invocation admission response behind the
temporary daemon-core command path, so omitted Rust-authored `receipt_refs`,
`artifact_refs`, `payload_refs`, and `authority_grant_refs` stopped becoming
invented empty arrays as compatibility truth.

That fallback-retirement slice is now superseded by the worker/service package
core API cut: the JS runner and normalizer are deleted, and the product route
reaches Rust-owned package admission through mounted `workerServicePackageCore`.
The target remains direct Rust daemon-core worker/service package protocol/API
ownership over StepModuleRouter admission, wallet authority, receipt/state-root
binding, Agentgres truth, projection, replay, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1155 retired JS-side trigger/receipt ref fallback synthesis from the
temporary L1 settlement runner. Rust `governed_admission.rs` already owned L1
settlement trigger admission and response shaping behind the temporary
daemon-core command path, so omitted Rust-authored `trigger_refs` and
`receipt_refs` stopped becoming invented empty arrays at the JS edge.

That fallback-retirement slice is now superseded by the L1 settlement core API
cut: the JS runner and normalizer are deleted, and the product route reaches
Rust-owned settlement admission through mounted `l1SettlementCore`. The current
transport cut then moves that core to typed
`daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt` and retires the old
Rust command operation. The remaining target is richer Rust daemon-core
settlement projection/replay over wallet authority where applicable,
receipt/state-root binding, Agentgres truth, and stable IDE/CLI/SDK protocol
surfaces.

Slice 1156 retired JS-side Agentgres head and receipt-ref fallback synthesis
from the then-temporary governed-improvement runner. That fallback-retirement
slice is now superseded by the governed-improvement core API cut: the JS runner
and normalizer are deleted, the daemon store mounts `governedImprovementCore`,
and the product route reaches Rust-owned proposal admission through that mounted
core. The current transport cut then moves that core to typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal` and
retires the old Rust command operation. The remaining target is richer Rust
daemon-core governed-improvement execution/projection/replay over Agentgres
admission, receipt/state-root binding, wallet approval, rollback metadata, and
stable IDE/CLI/SDK protocol surfaces.

Slice 1157 retired JS-side runtime Agentgres ref/evidence fallback synthesis
from the then-live Agentgres admission runner. Rust `agentgres_admission.rs`
and `agentgres_command.rs` already owned storage-write admission and runtime
state-commit response shaping behind the temporary daemon-core command path, so
the JS edge stopped inventing empty `artifact_refs`, `payload_refs`,
`receipt_refs`, or `evidence_refs`.

That runner-normalizer cleanup is now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut: the JS runner and normalizers are deleted,
and the core returns Rust daemon-core Agentgres envelopes as-is. The remaining
target is direct Rust daemon-core Agentgres protocol/API ownership over
expected-head checks, state-root binding, storage admission, durable write
materialization, projection, replay, and stable IDE/CLI/SDK protocol surfaces.

Slice 1158 retired JS-side workspace snapshot capture ref fallback synthesis
from the then-live workspace restore runner. Rust `workspace_restore.rs` already
owned workspace restore apply-policy, preview/apply operation, and snapshot
capture response shaping, so `runtime-workspace-restore-runner.mjs` preserved
omitted Rust-authored per-file `receipt_refs` and `artifact_refs` as `null`
instead of inventing empty arrays at the JS edge.

That runner-normalizer cleanup is now superseded by the typed workspace restore
API cut: the JS runner, generic command invoker, Rust workspace restore command
operations, shared daemon-core command runner, and Node bridge transport no
longer carry workspace restore/snapshot requests to Rust. The remaining target
is richer Rust daemon-core workspace snapshot/restore projection and replay
ownership over durable storage, receipt/state-root binding, Agentgres
ArtifactRef/PayloadRef admission, and stable IDE/CLI/SDK protocol surfaces, not
preservation of JS normalizers as compatibility shims.

Slice 1159 retired JS-side run-state materialization fallback synthesis from
the then-live runtime Agentgres admission runner. Rust `agentgres_command.rs`
already owned the single `commit_runtime_run_state` response that derives the
transition, storage write-set, persisted records, and written record proof
behind the temporary daemon-core command path, so the JS edge stopped inventing
empty `records` and `written_records`. `thread-persistence.mjs` carried that
absence into its fail-closed proof check instead of normalizing omitted
`written_records` before rejecting the commit.

That interim cleanup is now superseded by the mounted
`runtimeAgentgresAdmissionCore` cut: the JS runner, normalizer, command/env
fallback, and shared command helper path are gone for runtime Agentgres, while
the remaining direct Rust Agentgres protocol/API work is to remove the
command-envelope request builder, local replay cache, and thread persistence
scaffolding.

Slice 1160 retires JS-side required-boundary evidence fallback synthesis from
the model_mount core. Rust model_mount required-boundary planners
already own backend-lifecycle, server-control, runtime-engine, tokenizer, and
route-control required records behind the temporary daemon-core command path,
so `model-mount-core.mjs` now preserves omitted Rust-authored
required-boundary `evidence_refs` as `null` instead of inventing empty arrays
from JS. If Rust includes evidence in the returned record or record details,
the temporary JS edge may pass that Rust-authored array through, but it may not
create compatibility proof material when Rust omits it.

At that cut, the JS model_mount core request builder, shared daemon-core command
runner, and Node bridge transport still carried model_mount required-boundary
requests to Rust. Later model_mount typed API cuts retired those command paths;
Slice 1229 also retires the generic model_mount invoker shim. The remaining
target is Rust daemon-core model_mount materialization/protocol ownership over
lifecycle/control/tokenizer/route admission, receipt/state-root binding,
Agentgres projection, replay, and stable IDE/CLI/SDK protocol surfaces, not
preservation of JS normalizers as compatibility shims.

Slice 1161 retires JS-side StepModuleResult receipt and result fallback
authorship for coding-tool StepModule execution. `step-module-abi.mjs` no
longer invents `receipt://projection/...` refs for successful coding-tool
StepModule results; accepted coding-tool results now require explicit
Rust-owned receipt refs just like the Rust `StepModuleResult` validator. The
Rust-workload StepModule runner now builds only the StepModule invocation before
calling Rust and preserves an omitted Rust result as `null` instead of falling
back to a JS-authored projection result.

This remains non-terminal because the JS StepModule ABI helper, shared
daemon-core command runner, and `ioi-step-module-bridge` transport still carry
the invocation to Rust. The target is direct Rust daemon-core StepModuleRouter,
workload-client, receipt-binder, Agentgres-admission, and projection ownership
over invocation/result construction, execution, receipt/state-root binding,
replay, and stable IDE/CLI/SDK protocol surfaces, not preservation of JS result
projection as a compatibility fallback.

Slice 1162 retires JS-side receipt and policy-decision synthesis from
runtime context-pressure alert projection. `runtime-usage-events.mjs` may still
produce advisory `context.pressure_alert` projection rows for the protocol/UI
edge, but those alerts now carry empty `receipt_refs` and
`policy_decision_refs` unless a future Rust-owned policy/receipt admission path
provides admitted refs. The JS producer no longer mints
`receipt_context_pressure...` or `policy_context_pressure...` identifiers for
alert projection.

This remains non-terminal because runtime usage/context-pressure projection is
still assembled by JS while direct Rust daemon-core projection and policy APIs
are pending. The target is Rust daemon-core ownership of usage telemetry,
context-budget policy, receipt/policy admission, Agentgres-backed projection,
replay, and stable IDE/CLI/SDK protocol surfaces, not preservation of JS
advisory alerts as a source of accepted receipt or policy truth.

Slice 1163 retires JS-side receipt and policy-decision synthesis from
diagnostics feedback projection. `diagnostics-feedback.mjs` may still compact
post-edit diagnostics into advisory injected context, repair-retry context, and
blocking-gate projection rows for the protocol/UI edge, but it no longer mints
`receipt_lsp_diagnostics...`, `receipt_lsp_diagnostics_gate...`, or
`policy_lsp_diagnostics_gate...` fields for those advisory records. Existing
receipt refs from Rust/admitted diagnostic events may pass through; diagnostics
repair policy projection now contributes Rust policy projection receipt refs,
while deeper repair, retry, override, and gate admission receipts still must come
from Rust-owned diagnostics-repair admission paths.

This remains non-terminal because diagnostics feedback still collects temporary
diagnostic event facts in JS while direct Rust daemon-core diagnostics repair
admission, receipt/policy binding, Agentgres-backed durable projection/replay,
and stable IDE/CLI/SDK APIs are pending. The target is not preservation of JS
diagnostics feedback helpers as accepted truth authors; they are temporary
protocol/context scaffolding only.

The diagnostics repair policy-projection cut supersedes the earlier
snake_case-only JS policy scaffolding. `project_runtime_diagnostics_repair_policy`
is now a Rust daemon-core operation that receives runtime `state_dir` plus
diagnostic event ids, replays admitted Agentgres runtime events to derive
diagnostic status/count, rollback refs, snapshot refs, source tool-call refs,
repair contexts, and deterministic injection id, then returns the rollback
repair policy/config, decision refs, projection receipt refs, evidence refs, and
projection hash. Pending diagnostics feedback calls that Rust projector before
returning a blocking feedback envelope, and blocking-gate creation fails closed
when the Rust policy projection is absent or malformed.

The JS `diagnosticsRollbackRepairPolicy`, default-decision helper, and
context-policy aggregation facade are retired. The follow-on replay cut also
retires JS policy-input candidate transport for `diagnostic_status`,
`diagnostic_count`, `workspace_snapshot_refs`, `rollback_refs`,
`source_tool_call_ids`, `diagnostics_repair_contexts`, and `receipt_refs`.
`diagnostics-feedback.mjs` still selects diagnostic event ids and compacts prompt
text from the event stream, but it no longer supplies rollback repair policy
inputs or authors rollback repair policy truth. The diagnostics feedback
surface mounts the context-policy runner as the diagnostics repair policy
projector and refuses pending feedback policy projection without that Rust
boundary.

This remains non-terminal because broader diagnostics orchestration,
expected-head/state-root binding, receipt/policy binding, durable
projection/replay, and stable IDE/CLI/SDK protocol
APIs are still pending beyond the Rust policy replay projection API. The
operator-override issuance edge is now wallet-gated by Rust for
approval-required overrides, while the target remains no JS repair policy object
or policy-input authoring as accepted truth.

Slice 1166 retires JS-side artifact-read receipt synthesis from the temporary
coding-tool artifact read/retrieve adapter. `runtime-coding-tool-results.mjs`
now passes through existing admitted `artifactRecord.receipt_refs` and leaves
`receipt_refs` empty when Rust/Agentgres did not provide them; it no longer
constructs `receipt_artifact_read...` identifiers from the artifact id and byte
range. The helper also no longer depends on `safeId` for retired receipt-id
construction.

This has since advanced: artifact read/retrieve projection now calls Rust
daemon-core `project_runtime_coding_tool_artifact_read` with runtime
`state_dir`, and Rust replays committed `artifacts/*.json` Agentgres records,
filters canonical Rust-authored coding-tool artifacts, enforces thread
ownership and canonical target/range aliases, shapes byte ranges/result
metadata/receipt refs, rejects retired `artifact_records` candidate transport,
and fails closed when the projector or `state_dir` is absent. This is still
non-terminal because richer ArtifactRef/PayloadRef admission, receipt binding,
expected-head/state-root checks, runner transport retirement, and stable
protocol APIs remain pending.

Slice 1167 retires the remaining coding-tool response facade inside the
temporary Rust Node bridge module. `ioi_step_module_bridge/mod.rs` now imports
`file_apply_patch_response`, `artifact_read_response`,
`tool_retrieve_result_response`, and `computer_use_request_lease_response`
directly from `crates/services/src/agentic/runtime/kernel/coding_tool_step_module.rs`
for bridge proof tests instead of defining bridge-local wrapper functions and
bridge-local `CodingToolStepModuleCommandError` remapping glue.

This remains non-terminal because the Node bridge itself is still fixed
migration transport. The target is direct Rust daemon-core StepModule/coding
tool protocol APIs, where the bridge no longer exists as a long-term endpoint
and coding-tool response authorship, admission, receipt/state-root binding,
Agentgres persistence, replay, and projection stay in the Rust daemon core.

Slice 1168 moves the temporary bridge transport error type out of the broad
`ioi_step_module_bridge/mod.rs` module and into
`ioi_step_module_bridge/bridge_dispatch.rs`. `BridgeError` and the raw
`run_bridge()` stdin/JSON transport helper are now private to the dispatch
module; the broad bridge module only re-exports
`run_bridge_response_from_stdin()` for the temporary binary entry point.

This remains non-terminal because stdin/JSON command transport still exists as
migration scaffolding. The target is direct Rust daemon-core protocol APIs that
remove the Node bridge path entirely after StepModule/coding-tool dispatch,
receipt/state-root binding, Agentgres admission, replay, and projection are
owned end to end by the Rust daemon core.

Slice 1169 scopes the remaining bridge proof schema constants into the Rust
test module. `CODING_TOOL_RESULT_SCHEMA_VERSION` and
`MODEL_MOUNT_RUNTIME_SCHEMA_VERSION` no longer live at broad bridge runtime
module scope; after Slice 1171 they live in
`ioi_step_module_bridge/proof_tests.rs`, where the bridge proof assertions use
them.

This remains non-terminal because the broad bridge module still hosts the
temporary proof suite. The target is direct Rust daemon-core protocol APIs and
focused owner tests where the Node bridge no longer exists as a long-term
endpoint or proof surface.

Slice 1170 moves Rust service-owner and workload-client imports out of
production `ioi_step_module_bridge/mod.rs` scope and into the Rust test module.
The production bridge module now exposes only the temporary dispatch re-export;
the broad proof suite may still import Rust owners, but only behind
`#[cfg(test)]`.

This remains non-terminal because the bridge proof suite still lives beside the
temporary Node bridge endpoint. The target is direct Rust daemon-core protocol
APIs and focused owner tests where no production bridge module imports Rust
owner families as if they were bridge-owned runtime surface.

Slice 1171 extracts the temporary Rust bridge proof suite out of production
`ioi_step_module_bridge/mod.rs` and into
`ioi_step_module_bridge/proof_tests.rs`. The production bridge module is now
only `bridge_dispatch`, the temporary `run_bridge_response_from_stdin()`
re-export, and `#[cfg(test)] mod proof_tests;`.

This remains non-terminal because `proof_tests.rs` still proves the temporary
Node bridge endpoint. The target is direct Rust daemon-core protocol APIs with
focused owner tests in the Rust kernel/service modules, after which the bridge
endpoint and its proof surface can be retired rather than maintained as
canonical architecture.

Slice 1172 moves command schema-alias, unknown-operation, daemon-core
schema-family mismatch, and StepModule schema-family mismatch proofs out of
`ioi_step_module_bridge/proof_tests.rs` and into the Rust command protocol
owner at `crates/services/src/agentic/runtime/kernel/command_protocol.rs`.
Bridge conformance now requires the owner tests and proves the old
bridge-named command-protocol proof tests are absent from the temporary bridge
proof surface.

This remains non-terminal because `proof_tests.rs` still contains many
temporary bridge endpoint proofs. The target is to keep migrating generic
protocol, authority, admission, receipt, projection, and replay proof coverage
into Rust owner modules until the bridge proof surface can disappear.

Slice 1173 moves the remaining generic daemon-core rejects-StepModule-schema
proofs out of `ioi_step_module_bridge/proof_tests.rs` and into a catalog-wide
Rust owner test in
`crates/services/src/agentic/runtime/kernel/command_protocol.rs`. The bridge
proof suite no longer carries per-surface
`*_rejects_step_module_command_schema` duplicates for authority, approval,
workspace restore, cTEE, worker/service package, L1 settlement,
governed-improvement, context policy, runtime control, lifecycle, MCP/memory,
runtime Agentgres, or model_mount command families. Bridge conformance now
requires the Rust `daemon_core_catalog_rejects_step_module_command_schema`
owner proof and proves those local bridge checks stay absent.

This remains non-terminal because `proof_tests.rs` still proves temporary
bridge endpoint behavior and the Node bridge is still migration transport. The
target is direct Rust daemon-core protocol APIs where schema-family validation,
operation identity, dispatch, authority, admission, receipt/state-root binding,
projection, replay, and conformance are owned by Rust modules rather than by
bridge-local proof scaffolding.

Slice 1174 moves the Agentgres command-response proof family out of the
temporary bridge proof surface and into the Rust owner at
`crates/services/src/agentic/runtime/kernel/agentgres_command.rs`. Storage
backend write admission, runtime run-state commit, agent-state commit,
memory-state commit, subagent-state commit, artifact-state commit, model_mount
record-state commit, and model_mount receipt-state commit response/persistence
proofs now run as Agentgres command owner tests. Receipts conformance now
requires those `agentgres_command_*_through_rust_core` tests and proves the old
bridge proof names, request-type imports, and response-function aliases stay
absent from `ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because Agentgres command request/response shaping is
still exposed through temporary command transport. The target is direct Rust
daemon-core Agentgres protocol/API ownership where admitted truth, expected
heads/state roots, durable writes, replay, and conformance no longer depend on
Node bridge endpoint proof scaffolding.

Slice 1175 moves the approval command-response proof family out of the
temporary bridge proof surface and relies on the Rust approval owner at
`crates/services/src/agentic/runtime/kernel/approval.rs`. Coding-tool approval
manifest shaping plus approval request, decision, and revoke state-update
response shaping now run as `approval.rs` owner tests. Bridge conformance now
requires those Rust owner tests and proves the old bridge-named approval tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This was non-terminal at that cut because approval command shaping was still
reachable through temporary command transport. Subsequent approval API cuts move
coding-tool approval and public approval-state control/read to typed
`daemonCoreApprovalApi` methods and retire the old Rust approval command
operations. The target remains richer Rust daemon-core authority/approval
projection and replay ownership where approval admission, event materialization,
state updates, and conformance no longer depend on Node bridge endpoint proof
scaffolding.

Slice 1176 moves the governed authority/admission/receipt command-response
proof cluster out of the temporary bridge proof surface and relies on the Rust
owners at `crates/services/src/agentic/runtime/kernel/authority.rs`,
`crates/services/src/agentic/runtime/kernel/governed_admission.rs`, and
`crates/services/src/agentic/runtime/kernel/governed_receipt.rs`. External
capability authority, wallet.network negative authority, cTEE private workspace
receipt admission, worker/service package invocation receipt admission, L1
settlement admission, and governed meta-improvement proposal admission now run
as Rust owner tests. Bridge conformance now requires those owner tests and
proves the old bridge-named tests, request-type imports, and response-function
aliases stay absent from `ioi_step_module_bridge/proof_tests.rs`.

This was non-terminal at that cut because these operations still crossed
temporary command transport. Subsequent macro cuts retire that command transport
for external capability authority, cTEE, worker/service package invocation, L1
settlement, and governed-improvement proposal admission. The target remains
direct Rust daemon-core governed authority/admission protocol/API ownership
where wallet authority, cTEE custody, settlement
triggering, receipt binding, Agentgres admission, projection, replay, and
conformance no longer depend on Node bridge endpoint proof scaffolding.

Slice 1177 moves the admission-required policy command-response proof cluster
out of the temporary bridge proof surface and relies on the Rust policy owner at
`crates/services/src/agentic/runtime/kernel/policy/admission_required.rs`.
The projection-required half for public skill/hook registry, repository
workflow, runtime tool catalog, and runtime lifecycle is superseded by positive
Rust projection owner tests. Bridge and compositor conformance now require
those owner tests and prove the old bridge-named tests, request-type imports,
and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because these policy decisions still cross temporary
command transport. The target is direct Rust daemon-core policy/projection API
ownership where admission-required refusal, projection-required refusal,
Agentgres truth, replay, and conformance no longer depend on Node bridge
endpoint proof scaffolding.

Slice 1178 moves the context lifecycle command-response proof cluster out of
the temporary bridge proof surface and relies on the Rust policy owner at
`crates/services/src/agentic/runtime/kernel/policy/context_lifecycle.rs`.
Context-budget policy, coding-tool budget policy, compaction policy,
context-compaction plan, and context-compaction state-update response shaping
now run as Rust owner tests. Bridge conformance now requires those owner tests
and proves the old bridge-named context lifecycle tests, request-type imports,
and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because durable context lifecycle replay/projection,
richer policy receipts/state roots, wallet/cTEE authority, and stable
IDE/CLI/SDK APIs still need direct Rust ownership. Public context compaction is no longer a
fail-closed JS facade: `compactThread()` now uses Rust event planning, Rust
runtime-event admission, Rust state-update planning bound to the admitted event
id/seq, and Agentgres-backed run/agent persistence. Thread/run context-budget and
thread compaction-policy are now Rust policy-event admission paths instead of
fail-closed JS facades, and approved compaction-policy execution routes through
the Rust-owned compaction API. Schedule the next
matrix-compaction pass only after the next direct Rust-core API extraction or
facade-retirement seam makes it clear which temporary transport rows can be
collapsed without canonizing the bridge.

The context lifecycle transport cut after Slice 1178 replaces the temporary
context lifecycle command path with typed `daemonCoreContextLifecycleApi`
methods for context-budget policy, coding-tool budget policy, coding-tool
budget-block planning, compaction-policy, context-compaction planning, and
context-compaction state-update planning. The JS runtime context-policy core now
sends canonical request bodies to that typed API without generic command
`operation`/`backend` envelopes, and Rust `command_protocol.rs`/
`command_dispatch.rs` reject the old context lifecycle command operations. This
does not claim terminal context-policy migration: durable replay/projection,
richer policy receipts/state roots, wallet/cTEE authority, stable IDE/CLI/SDK
APIs, and the remaining non-context lifecycle state-update families still need
direct Rust ownership.

Slice 1179 moves the runtime-control command-response proof cluster out of the
temporary bridge proof surface and relies on the Rust policy owners at
`crates/services/src/agentic/runtime/kernel/policy/coding_tool_budget_recovery.rs`,
`crates/services/src/agentic/runtime/kernel/policy/operator_control.rs`, and
`crates/services/src/agentic/runtime/kernel/policy/run_cancel.rs`. Coding-tool
budget recovery state-update and admission-required responses, diagnostics
operator override state-update responses, operator turn-control
admission-required responses, operator interrupt/steer state-update responses,
and the then-current run-cancel state-update/admission-required responses moved
to Rust owner tests. Bridge conformance now requires those owner tests and proves the old
bridge-named runtime-control tests, request-type imports, and response-function
aliases stay absent from `ioi_step_module_bridge/proof_tests.rs`.
Slice 1230 retires the remaining run-cancel command-shaped owner wrappers from
that intermediate proof cluster.

The runtime-control transport cut after Slice 1179 replaces that temporary
command path with typed `daemonCoreRuntimeControlApi` methods for coding-tool
budget recovery state/control planning, diagnostics operator override
state-update planning, operator turn-control admission-required planning,
operator interrupt/steer state-update planning, and run-cancel
state/admission planning. The JS runtime context-policy core now sends
canonical request bodies to that typed API without generic command
`operation`/`backend` envelopes, the Rust kernel exposes the corresponding
positive daemon-core methods, and `command_protocol.rs`/`command_dispatch.rs`
reject the old runtime-control command operations. This does not claim
terminal runtime-control migration: durable replay/projection, richer
runtime-control receipts/state roots, wallet/runtime-control authority, stable
IDE/CLI/SDK APIs, and the remaining MCP/memory families still need direct Rust
ownership.

The thread-lifecycle state-update transport cut after Slice 1180 replaces the
temporary command path with typed `daemonCoreThreadLifecycleApi` methods for
thread-control agent state updates, runtime-bridge thread start/control state
updates, runtime-bridge turn run state updates, subagent record state updates,
agent/thread/run creation state updates, and agent status/delete state updates.
The JS runtime context-policy core now sends canonical request bodies to that
typed API without generic command `operation`/`backend` envelopes, the Rust
kernel exposes the corresponding positive daemon-core methods, and
`command_protocol.rs`/`command_dispatch.rs` reject the old thread-lifecycle
state-update command operations. This retires the command transport for the
runtime-bridge thread-control/start/turn-submit, agent-run-create, thread
control, and subagent-wait state-update hot paths guarded by bridge and
compositor conformance. This does not claim terminal lifecycle migration:
durable replay/projection, wallet/cTEE lifecycle authority, stable
IDE/CLI/SDK APIs, and MCP/memory policy/control transport remain non-terminal;
Slice 1223 later retires the thread-turn and lifecycle admission-required
command transport through typed lifecycle APIs.

Slice 1180 moves the thread-lifecycle and MCP/memory command-response proof
clusters out of the temporary bridge proof surface and relies on the Rust
policy owners at
`crates/services/src/agentic/runtime/kernel/policy/thread_lifecycle.rs` and
`crates/services/src/agentic/runtime/kernel/policy/mcp_memory.rs`. Thread
control, thread-turn admission-required, lifecycle admission-required,
runtime-bridge thread/turn state updates, subagent state updates,
agent/run lifecycle state updates, MCP control, MCP server validation/input,
MCP manager status/catalog/catalog-summary/validation, memory manager
status/validation, and thread-memory state-update command-response shaping now
run as Rust owner tests. Bridge conformance now requires those owner tests and
proves the old bridge-named thread/MCP/memory tests, request-type imports, and
response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because MCP/memory policy decisions still cross
temporary command transport. Thread-turn and lifecycle admission-required
refusals were later moved to typed Rust daemon-core lifecycle APIs, so they are
no longer a current command-transport blocker. The target is direct Rust
daemon-core MCP and memory API ownership where admission, projection,
Agentgres truth, replay, and conformance no longer depend on Node bridge
endpoint proof scaffolding.

The workspace-trust state-update transport cut replaces the temporary command
path with typed `daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate`.
The JS runtime context-policy core now sends canonical workspace-trust
warning/ack request bodies to that typed API without generic command
`operation`/`backend` envelopes, the Rust kernel exposes the corresponding
positive daemon-core method, and `command_protocol.rs`/`command_dispatch.rs`
reject the old workspace-trust state-update command operation. This retires the
command transport for the workspace-trust warning/ack hot path guarded by
compositor conformance; deeper wallet/cTEE workspace authority, durable
projection storage, and stable SDK/IDE/CLI APIs remain non-terminal.

Slice 1181 moved the workspace-restore command-response proof cluster out of
the temporary bridge proof surface and into the Rust workspace owner at
`crates/services/src/agentic/runtime/kernel/workspace_restore.rs`. That
proof move is now superseded by the typed workspace restore API cut: workspace
restore apply-policy planning, restore operation preview/apply, workspace
snapshot capture, snapshot projection, content-package projection, and restore
preview/apply all enter Rust through `daemonCoreWorkspaceRestoreApi`, and the
old workspace restore command catalog/dispatch operations are retired. The
remaining target is richer durable Rust daemon-core workspace snapshot/restore
projection and replay ownership where Agentgres truth, receipt/state-root
binding, and stable IDE/CLI/SDK surfaces no longer depend on thin JS protocol
client scaffolding.

Slice 1182 moves the first model-mount admission/execution command-response
proof cluster out of the temporary bridge proof surface and relies on the Rust
model-mount owners at
`crates/services/src/agentic/runtime/kernel/model_mount/admission.rs` and
`crates/services/src/agentic/runtime/kernel/model_mount/provider_execution.rs`.
Route-decision admission, invocation admission, provider-execution admission,
fixture provider invocation, native-local provider invocation, and
native-local provider stream command-response shaping now run as Rust owner
tests. Bridge conformance now requires those owner tests, proves typed Rust
`command_dispatch.rs` still dispatches those operations, and proves the old
bridge-named tests, request-type imports, and response-function aliases stay
absent from `ioi_step_module_bridge/proof_tests.rs`.

This remains non-terminal because model-mount admission and provider execution
still cross temporary command transport. The target is direct Rust daemon-core
model-mount protocol/API ownership where route selection, invocation
admission, provider execution, provider invocation, Agentgres truth, replay,
and stable IDE/CLI/SDK surfaces no longer depend on Node bridge endpoint proof
scaffolding.

Slice 1183 moved the next model-mount provider-result and receipt-binding
command-response proof cluster out of the temporary bridge proof surface and
into the Rust owners at
`crates/services/src/agentic/runtime/kernel/model_mount/provider_result.rs`
and `crates/services/src/agentic/runtime/kernel/model_mount_receipt.rs`.
Provider-result command-envelope shaping and the then-command-shaped receipt
binding proofs moved to Rust owner tests first; later cuts moved provider-result
admission and invocation receipt binding to typed `daemonCoreModelMountApi`
methods and removed their command operations from Rust protocol/dispatch. The
target remains direct Rust daemon-core model-mount protocol/API ownership for
the remaining transport families.

Slice 1184 moves the model-mount provider lifecycle, provider inventory, and
instance lifecycle command-response proof cluster out of the temporary bridge
proof surface and into the Rust owner at
`crates/services/src/agentic/runtime/kernel/model_mount/lifecycle.rs`.
Provider lifecycle, provider inventory, and instance lifecycle command-envelope
response shaping now run as Rust owner tests. Bridge conformance now requires
those owner tests, proves typed Rust `command_dispatch.rs` still dispatches
`plan_model_mount_provider_lifecycle`,
`plan_model_mount_provider_inventory`, and
`plan_model_mount_instance_lifecycle`, and proves the old bridge-named tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`. The bridge proof suite now runs 41
tests.

This remains non-terminal because provider lifecycle, provider inventory, and
instance lifecycle planning still cross temporary command transport. The target
is direct Rust daemon-core model-mount protocol/API ownership where provider
lifecycle execution, provider inventory materialization, instance lifecycle
transition admission, Agentgres truth, replay, and stable IDE/CLI/SDK surfaces
no longer depend on Node bridge endpoint proof scaffolding.

Slice 1185 moves the model-mount backend-process and required-control
command-response proof cluster out of the temporary bridge proof surface and
into Rust model-mount owners at
`crates/services/src/agentic/runtime/kernel/model_mount/backend_process.rs`
and `crates/services/src/agentic/runtime/kernel/model_mount/required.rs`.
Backend process planning plus tokenizer and route-control required
response shaping now run as Rust owner tests, while backend
lifecycle now has positive command-envelope and record-planning owner tests in
Rust `model_mount/backend_lifecycle.rs`. Bridge
conformance now requires those owner tests, proves Slice 1222 retired the
`plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle` command operations, and proves Slice 1220
retired `plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer`, while public route write/test,
mounted route selection, explicit-model endpoint resolution, and runtime
explicit/run-override model-route selection now call typed
`daemonCoreModelMountApi.planModelMountRouteControl`, backed by Rust
`RuntimeKernelService::plan_model_mount_route_control`, and runtime-engine
selection/profile/remove mutations now call typed `daemonCoreModelMountApi.planModelMountRuntimeEngine`, backed by Rust `RuntimeKernelService::plan_model_mount_runtime_engine`, with Rust Agentgres model_mount record-state commits. The owner tests prove the required route-control record family for unmigrated helper edges, the positive runtime-engine direct API, and the retired runtime-engine command transport, while `command_protocol.rs` now rejects the retired
`plan_model_mount_route_control` operation and the old bridge-named tests,
request-type imports, and response-function aliases stay absent from
`ioi_step_module_bridge/proof_tests.rs`. Server-control later moved to the
positive `plan_model_mount_server_control` boundary and its required-record
command stayed retired; runtime-engine likewise moved to typed `daemonCoreModelMountApi.planModelMountRuntimeEngine` and retired its command transport plus required-record command;
backend lifecycle likewise moved to positive
`plan_model_mount_backend_lifecycle`, retired its required-record command, and
then Slice 1222 moved backend-process/backend-lifecycle planning to typed
daemon-core APIs. The
bridge proof suite now runs 35 tests.

This remains non-terminal because actual backend process supervision/transport
execution and live external backend process-state supervision still need Rust
ownership. Backend-process/backend-lifecycle planning, public route-control, and
model_mount conversation/stream planning no longer cross temporary command
transport. The target is direct Rust daemon-core model-mount protocol/API
ownership where backend supervision, tokenizer/context-fit control, Agentgres truth, replay, and stable
IDE/CLI/SDK surfaces no longer depend on Node bridge endpoint proof scaffolding.

Slice 1186 moved the remaining model-mount accepted-receipt proof cluster and
the then-temporary read-projection proof cluster out of the temporary bridge
proof surface and into Rust owners at
`crates/services/src/agentic/runtime/kernel/model_mount_receipt.rs` and
`crates/services/src/agentic/runtime/kernel/model_mount/read_projection.rs`.
Accepted-receipt head/transition planning and read-projection have since moved
to positive typed APIs owned by `RuntimeKernelService`; Rust command protocol
now rejects `plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt`. This remains non-terminal only because
other model_mount helpers still cross temporary transport.

Slice 1187 deletes the remaining temporary bridge proof module and moves its
coding-tool StepModule proof obligations into Rust owner tests. The Node bridge
module now exports only the temporary stdin/JSON transport entry point through
`bridge_dispatch.rs`; `ioi_step_module_bridge/proof_tests.rs` is absent and
`cargo test -p ioi-node --bin ioi-step-module-bridge` runs zero semantic bridge
tests. Coding-tool StepModule response/admission/receipt/projection coverage
now lives in
`crates/services/src/agentic/runtime/kernel/coding_tool_step_module.rs`, while
workspace execution/inspection coverage remains in
`crates/services/src/agentic/runtime/kernel/coding_tool_workspace.rs`.
Bridge conformance now requires the Rust owner test names for file patch,
artifact read, result retrieval, and computer-use request-lease alias/authority
proofs, and proves the bridge proof module and its service-owner imports stay
absent.

This remains non-terminal because the Node bridge is still temporary command
transport. The target is direct Rust daemon-core StepModule/coding-tool
protocol/API ownership where command-envelope validation, dispatch, workload
execution, receipt binding, Agentgres admission, replay, projection, and stable
IDE/CLI/SDK surfaces no longer require a Node bridge binary at all.

Slice 1188 was an intermediate contraction of the StepModule-specific command
path at the JS runner edge. It was superseded by the typed workload API cut and
the later command-env deletion: `createStepModuleRunnerFromEnv()` no longer
reads `IOI_STEP_MODULE_COMMAND` or `IOI_RUNTIME_DAEMON_CORE_COMMAND`, and no
command env is a live StepModule source.

Slice 1189 was the intermediate daemon-core command-schema contraction for
coding-tool StepModule dispatch. It was superseded by Slice 1228 and then
Slice 1262: the live coding-tool invocation surface no longer emits any command
schema or command envelope for `run_coding_tool_step_module`; it calls typed
`daemonCoreWorkloadApi.runCodingToolStepModule` directly, while the deleted command-protocol source plus conformance source scans keep
`run_coding_tool_step_module` absent as a command operation. The old StepModule and daemon-core command schemas remain
only as rejected legacy evidence.

Slice 1190 removes the dead StepModule command-family/catalog API left behind
after Slice 1189. `command_protocol.rs` no longer exposes
`STEP_MODULE_OPERATIONS`, `CommandFamily`, `command_family()`,
`is_step_module_operation()`, or `is_daemon_core_operation()`; all live
temporary command operations resolve their schema directly through
`CommandOperation::schema_version()` and the daemon-core operation catalog. The
retired `ioi.step_module.command_bridge.v1` schema constant remains only for
negative tests that prove legacy StepModule command envelopes fail closed.
Bridge conformance now rejects reintroducing the dead family API while still
requiring Rust-owned typed command operation validation before dispatch.

This remains non-terminal because the unified daemon-core command protocol
still crosses temporary Node-launched transport. The target is direct Rust
daemon-core StepModuleRouter/coding-tool protocol/API ownership where command
validation, dispatch, workload execution, receipt binding, Agentgres admission,
replay, projection, and stable IDE/CLI/SDK surfaces do not depend on
command-bridge transport.

Slice 1191 moves the temporary stdin/JSON daemon-core command transport owner
out of `crates/node/src/bin/ioi_step_module_bridge/bridge_dispatch.rs` and into
Rust service-kernel ownership in `command_dispatch.rs`. The deleted bridge
module no longer owns `BridgeError`, raw `run_bridge()` parsing, canonical
`CommandEnvelope` validation, schema-alias rejection, operation dispatch, or
the `{ ok, result/error }` response envelope. `ioi-step-module-bridge` remains
only a temporary binary entry point that calls
`run_daemon_core_command_response_from_stdin()` from `ioi-services`.

This is still non-terminal because JS runners can still spawn the temporary
binary through `IOI_RUNTIME_DAEMON_CORE_COMMAND`. It is nevertheless a larger
pure-Rust cut: command transport semantics, error mapping, envelope validation,
and dispatch framing are now owned by the Rust daemon-core service boundary,
and conformance fails if the deleted bridge-local transport module is
recreated. Resume by replacing the remaining JS command invoker and binary
spawn path with direct Rust daemon-core protocol/API calls.

Slice 1192 removed the last live transport re-export from
`crates/node/src/bin/ioi_step_module_bridge/mod.rs`. Later Slice 1233 deleted
the temporary `ioi-step-module-bridge` binary and the empty
`ioi_step_module_bridge/mod.rs` tombstone, and Slice 1234 deleted the
`command_dispatch.rs` stdin/JSON transport; conformance now proves retired bridge
wrappers, proof modules, helper imports, command facades, binary fallback, and
service command dispatch are not recreated.

This is not terminal because the JS daemon still invokes the temporary binary.
It does remove another compatibility shim from the live path: there is no
bridge module between the temporary process entry point and the Rust
service-kernel command transport owner. Resume by replacing
`runtime-daemon-core-command-runner.mjs` and its `IOI_RUNTIME_DAEMON_CORE_COMMAND`
spawn path with direct Rust daemon-core protocol/API calls.

Slice 1193 adds an explicit direct Rust daemon-core API seam to the shared JS
daemon-core command invoker. `runtime-daemon-core-command-runner.mjs` now
accepts `daemonCoreInvoker`, runs it before the temporary binary spawn path,
and preserves missing-command fail-closed behavior when neither a direct
invoker nor the migration command is configured. The current StepModule,
approval, context-policy, governed-improvement, worker/service package,
workspace-restore, L1 settlement, external capability, model_mount core,
runtime Agentgres, and cTEE private workspace runners thread
`options.daemonCoreInvoker` through their environment factories and
constructors.

This is not terminal direct Rust ownership. It is the reviewed migration seam
for the next larger cut: wire the seam to real Rust daemon-core protocol/API
entry points, then delete the `IOI_RUNTIME_DAEMON_CORE_COMMAND` binary-spawn
fallback and the JS command invoker scaffolding once conformance proves every
hot-path surface is owned by Rust daemon-core APIs.

Slice 1194 removes the shared JS-authored `mockResult` command fallback from
`runtime-daemon-core-command-runner.mjs` and from all current daemon-core
command runners that used that shared helper. Tests that need an in-process
Rust-core substitute now use `daemonCoreInvoker` explicitly, while passing the
retired `mockResult` option without a direct invoker or migration command fails
closed instead of producing a JS-authored result.

This is still not terminal because the temporary binary-spawn fallback remains
for surfaces that have not yet been wired to direct Rust daemon-core APIs. It
does remove one duplicate JS truth/result path from the migration scaffolding:
there is now a single reviewed direct-invoker seam for in-process Rust API
wiring and one explicit binary-spawn fallback to delete after that wiring is
verified.

Slice 1195 lifted the direct daemon-core invoker seam from per-runner test
plumbing into the daemon composition boundary. At that historical cut,
`AgentgresRuntimeStateStore` accepted `daemonCoreInvoker`, stored it once, and
passed it through the default runtime Agentgres, context-policy,
governed-improvement, external capability, worker/service package, cTEE private
workspace, L1 settlement, workspace restore, model_mount core, and StepModule
runner construction paths. Later typed-core cuts retire that generic invoker,
and Slice 1262 deletes the temporary StepModule runner facade; the live
coding-tool invocation surface receives `daemonCoreWorkloadApi` directly.

This is still migration scaffolding, not terminal direct Rust ownership. It
does make the next pure-Rust cut larger and cleaner: a real Rust daemon-core
API can now be injected at the daemon boundary and exercised across default
hot-path runners before the `IOI_RUNTIME_DAEMON_CORE_COMMAND` spawn fallback and
JS command invoker are deleted.

Slice 1203 retires the daemon L1 settlement runner outright. The daemon store
now mounts `l1SettlementCore`; the JS runner facade, store runner option,
command/env fallback, and response normalizer are deleted.

The governed-admission transport cut supersedes that direct-invoker-only edge:
the L1 settlement core now requires typed
`daemonCoreGovernedAdmissionApi.admitL1SettlementAttempt`, rejects generic
`daemonCoreInvoker`, calls Rust with the canonical attempt plus thread/agent
route context, and returns the Rust `governed_admission.rs` admission protocol
envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_l1_settlement_attempt` absent as a daemon-core command operation, so the old
command-envelope path cannot be selected for this migrated family.

This removes JS envelope truth for the settlement path: trigger admission,
settlement refs, trigger refs, receipt refs, state-root refs, admission hashes,
source, and backend truth must arrive from Rust daemon-core output or remain
absent at the JS edge. A later state-root authority cut also removes
`state_root_ref` from daemon, SDK, IDE, and CLI request clients; Rust
`settlement.rs` derives admitted `state_root_ref` from canonical
settlement/domain/trigger/receipt facts and direct L1 attempts reject unknown
state-root input at the Rust schema boundary. It is still not terminal because
richer L1 settlement projection/replay records, deeper Agentgres
receipt/state-root binding, stable IDE/CLI/SDK settlement read APIs, and other
route-family command transports remain non-terminal.

Slice 1204 retires the daemon governed-improvement runner outright. The daemon
store now mounts `governedImprovementCore`; the JS runner facade, store runner
option, command/env fallback, and response normalizer are deleted.

The governed-admission transport cut supersedes that direct-invoker-only edge:
the governed-improvement core now requires typed
`daemonCoreGovernedAdmissionApi.admitGovernedRuntimeImprovementProposal`,
rejects generic `daemonCoreInvoker`, calls Rust with the canonical proposal plus
thread/agent route context, and returns the Rust `governed_admission.rs`
admission protocol envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_governed_runtime_improvement_proposal` absent as a daemon-core command
operation, so the old command-envelope path cannot be selected for this
migrated family.

This removes JS envelope truth for the governed-improvement path: expected
heads, eval/verifier receipt refs, proposal refs, admission hashes, Agentgres
operation refs, state roots, approval refs, rollback refs, source, and backend
truth must arrive from Rust daemon-core output or remain absent at the JS edge.
It is still not terminal because richer governed-improvement execution,
projection, and replay records, deeper Agentgres receipt/state-root binding,
stable IDE/CLI/SDK governed-improvement read APIs, and other route-family
command transports remain non-terminal.

Slice 1205 retires the daemon external capability authority runner outright.
The daemon store now mounts `externalCapabilityAuthorityCore`; the JS runner
facade, store runner option, command/env fallback, and response normalizer are
deleted.

The current external capability authority transport cut retires the remaining
generic command-envelope request builder for this family. The core now requires
typed `daemonCoreAuthorityApi.authorizeExternalCapabilityExit`, rejects the
retired `daemonCoreInvoker` command-transport option plus request aliases/truth
fields before Rust invocation, and returns the Rust `authority.rs`
wallet.network authority protocol envelope as-is. Rust `command_protocol.rs`
also rejects `authorize_external_capability_exit` as an absent command operation,
so this migrated authority path cannot return through the temporary command
dispatcher.

This removes JS envelope truth for the external capability path:
authorization booleans, wallet.network grant refs, authority receipt refs,
authority hashes, route context, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer authority projection/replay records, Agentgres
receipt/state-root binding, and stable IDE/CLI/SDK authority read APIs still
need direct Rust ownership, and other route families still carry temporary
command transport.

The current cTEE Private Workspace transport cut retires the remaining generic
command-envelope request builder for this family. The core now requires typed
`daemonCoreCteeApi.executePrivateWorkspaceCteeAction`, rejects the retired
`daemonCoreInvoker` command-transport option plus request aliases before Rust
invocation, and returns the Rust `governed_receipt.rs` cTEE custody protocol
envelope as-is. Rust `command_protocol.rs` also rejects
`execute_private_workspace_ctee_action` as an absent command operation, so this
migrated custody path cannot return through the temporary command dispatcher.

This removes JS envelope truth for the cTEE path: action execution booleans,
custody proof refs, receipt refs, accepted-receipt append, Agentgres admission,
projection records, route context, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer cTEE projection/replay records, Agentgres
receipt/state-root binding, and stable IDE/CLI/SDK cTEE read APIs still need
direct Rust ownership, and other route families still carry temporary command
transport.

Slice 1197 retired the temporary binary-spawn fallback for the daemon external
capability authority runner. That direct-invoker-only migration edge is now
superseded by the Slice 1205 core cut: the runner file is deleted,
`externalCapabilityAuthorityCore` is mounted on the daemon store, and external
capability authorization no longer has a command/env fallback or JS response
normalizer.

This makes the wallet.network authority path a mounted core API instead of a
runner facade: external capability authorization, grant refs, receipt refs,
authority hashes, and public envelope facts must arrive from Rust daemon-core
authority output or stay absent at the JS edge. It is still not terminal
daemon-wide Rust API ownership because other command runners remain on
temporary command transport. Resume by cutting the remaining authority,
admission, and projection runners the same way.

Slice 1198 retired the temporary binary-spawn fallback for the daemon governed
improvement runner. That direct-invoker-only migration edge is now superseded by
the Slice 1204 core cut: `runtime-governed-improvement-runner.mjs` is deleted,
`governedImprovementCore` is mounted on the daemon store, and proposal
admission no longer has a command/env fallback or JS response normalizer.

This makes the admitted-truth path a mounted core API instead of a runner
facade: proposal admission, expected-head/state-root binding fields,
evaluation receipts, verifier receipts, approval refs, and rollback refs must
arrive from Rust daemon-core admission output or stay absent at the JS edge. It
is still not terminal daemon-wide Rust API ownership because other command
runners remain on temporary command transport. Resume by cutting the remaining
admission and receipt-bearing runners the same way.

Slice 1199 retired the temporary binary-spawn fallback for the daemon cTEE
Private Workspace migration edge. The follow-on cTEE macro cut removes the
runner facade entirely: Private Workspace cTEE execution now reaches Rust
through mounted `cteePrivateWorkspaceCore`, command/env selection is not read,
and receipt-bearing cTEE execution, custody proof refs, receipt binding,
accepted receipt append, Agentgres admission, projection records, receipt refs,
and evidence refs must arrive from Rust daemon-core output.

The follow-on transport cut supersedes the direct-invoker-only edge: the cTEE
core now requires typed `daemonCoreCteeApi.executePrivateWorkspaceCteeAction`,
rejects generic `daemonCoreInvoker`, and the old Rust
`execute_private_workspace_ctee_action` command operation is retired. This is
still not terminal because the JS product surface remains a canonical request
extractor and richer cTEE projection/replay records, Agentgres
receipt/state-root binding, and stable IDE/CLI/SDK cTEE read APIs still need
direct Rust ownership.

Slice 1202 retires the daemon worker/service package runner outright. The
daemon store now mounts `workerServicePackageCore`; the JS runner facade, store
runner option, command/env fallback, and response normalizer are deleted.

The follow-on transport cut supersedes that direct-invoker-only edge: the
worker/service package core now requires typed
`daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation`, rejects
generic `daemonCoreInvoker`, calls Rust with the canonical invocation plus
thread/agent route context, and returns the Rust `governed_receipt.rs`
admission protocol envelope as-is. The deleted command-protocol source plus conformance source scans keep
`admit_worker_service_package_invocation` absent as a daemon-core command operation, so
the old command-envelope path cannot be selected for this migrated family.

This removes JS envelope truth for the receipt-bearing worker/service package
path: package admission, router admission, receipt binding, accepted receipt
append, Agentgres admission, projection records, receipt refs, artifact refs,
payload refs, authority grant refs, source, and backend truth must arrive from
Rust daemon-core output or remain absent at the JS edge. It is still not
terminal because richer package projection/replay records, deeper Agentgres
receipt/state-root binding, stable IDE/CLI/SDK package admission read APIs, and
other route-family command transports remain non-terminal.

Slice 1201 retires the temporary binary-spawn fallback for the daemon workspace
restore runner. `runtime-workspace-restore-runner.mjs` no longer imports the
shared JS daemon-core command invoker, no longer exposes or reads a live
`WORKSPACE_RESTORE_COMMAND_ENV`, and no longer accepts constructor command
selection or spawn hooks. Workspace restore apply-policy planning,
preview/apply operation planning, and snapshot capture now require the
daemon-level `daemonCoreInvoker` direct Rust-core seam and fail closed when it
is absent. `IOI_RUNTIME_DAEMON_CORE_COMMAND` and retired
`IOI_WORKSPACE_RESTORE_COMMAND` values are treated only as forbidden command
selection input for this surface, not as fallback transport.

This makes workspace snapshot/restore planning direct-invoker-only at the
daemon runner: policy decisions, restore operations, snapshot capture file
records, receipt refs, and artifact refs must arrive from Rust daemon-core
output or remain absent at the JS edge. It is still not terminal because the
JS product facade remains fail-closed scaffolding until direct Rust daemon-core
workspace snapshot/restore APIs own admission, artifact/payload refs,
Agentgres expected-head/state-root binding, projection, and replay end to end.
Resume by cutting the remaining command-transport runners, then delete the
shared JS command invoker once every live surface has a direct Rust daemon-core
API.

Slice 1202 retired the temporary binary-spawn fallback for daemon runtime
Agentgres admission. The follow-on Agentgres API cut retires the generic
`daemonCoreInvoker` seam for this family as well: `runtimeAgentgresAdmissionCore`
now requires typed `daemonCoreAgentgresApi` methods, rejects command/env/spawn
selection plus generic invoker options, and the migrated Agentgres operation
names are absent from Rust `CommandOperation`, `DAEMON_CORE_OPERATIONS`, and
`command_dispatch.rs`. Storage admission, expected-head/state-root derivation,
transition hashes, materialization/write-set/persistence/commit hashes, written
records, ArtifactRefs, PayloadRefs, receipt refs, and evidence refs must arrive
from Rust daemon-core Agentgres protocol output or remain absent at the JS edge.
Thread persistence remains a JS caller/cache facade around those Rust APIs, and
model_mount/context/StepModule still carry temporary command or invoker
transport.

Recent direct-invoker macro cut:
model_mount, context-policy/state-update, and StepModule surfaces still use
direct-invoker-only or mounted core scaffolding at the daemon layer. Runtime
Agentgres admission has since moved off the generic direct invoker to typed
`daemonCoreAgentgresApi` methods, approval-state and coding-tool approval moved
to typed `daemonCoreApprovalApi` methods, and workspace restore moved to typed
`daemonCoreWorkspaceRestoreApi` methods. The migrated surfaces no longer import
the shared JS daemon-core command invoker, accept constructor command selection,
accept constructor args, or treat `IOI_RUNTIME_DAEMON_CORE_COMMAND`,
`IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`, or surface-specific command envs as
fallback transport. The shared
`runtime-daemon-core-command-runner.mjs` helper and its test are deleted and
must not be recreated.

This macro cut also retires the coding-tool approval-satisfaction JS gate. The
mounted coding-tool governance surface no longer exports
`codingToolApprovalSatisfaction()`, no longer reads approval request events,
approval decision event streams, or lease-state helpers, and the daemon
composition no longer injects the approval lease, approval reason, or manifest
match helpers into that surface. Approval-required coding-tool execution now
asks the Rust daemon-core `planCodingToolApprovalSatisfaction` approval API
method before entering the StepModule path. Only a Rust satisfied record can carry the
approval id, decision event, receipt refs, and policy-decision refs into the
execution context; otherwise the path calls the Rust daemon-core
`planCodingToolApprovalBlock` approval API method and returns the Rust-shaped blocked
coding-tool result/event envelope. The stale JS `latestApprovalRequestEvent()`
readback facade and `blockCodingToolForApproval()` approval-block facade are
retired and must not be recreated.

This is a positive Rust approval-satisfaction and approval-block API cut, but
not terminal approval migration. Coding-tool result-event admission is now a
positive Rust daemon-core API: `admit_coding_tool_result_event` admits successful,
failed, and approval-blocked coding-tool result events with Agentgres storage
admission, receipt refs, expected heads, state roots, payload refs, and projection
watermarks before the JS daemon registers the Rust-returned event for replay.
The JS result-event admission hook is deleted, and approval-block persistence now
routes through the same Rust admission boundary.

Normal coding-tool result envelope/context planning is now a positive Rust
daemon-core API. The invocation surface calls `plan_coding_tool_result_envelope`
before workload dispatch for the StepModule context and again after workload
observation for the result `payload_summary` and runtime-event candidate before
Agentgres admission. The JS surface forwards canonical request/result facts,
validates the Rust plan, and fails closed before runner execution if the Rust
planner is absent; JS-authored StepModule context, source-event kind selection,
payload-summary construction, and candidate result-event truth are retired for
the migrated normal path.

Command-stream persistence is now a positive Rust daemon-core API too:
`admit_coding_tool_command_stream_events` owns canonical stream request
evaluation, stdout/stderr chunking, command-stream event materialization,
Agentgres storage admission, receipt refs, expected heads, state-root chaining,
payload refs, and projection watermarks before the JS daemon registers the
Rust-returned stream events for replay. The old JS command-stream append facade
is deleted and must not be recreated.

Coding-tool StepModule invocation construction is Rust-owned for migrated live
tools. `run_coding_tool_step_module` now accepts canonical coding-tool request
facts; Rust daemon-core owns the migrated tool contract table, input hashing,
invocation id generation, authority/custody/backend fields, workload dispatch
request construction, StepModuleRouter admission, receipt binding, Agentgres
admission, and projection record creation. The JS runner no longer imports the
coding-tool StepModule ABI builder or passes a JS-created `StepModuleInvocation`
into the command. A supplied coding-tool invocation envelope fails closed with
`js_step_module_invocation_retired`.

Patch workspace snapshot capture is now a Rust-owned hot-path follow-up for
`file.apply_patch`. Rust `workspace_restore.rs` emits canonical
`snapshot_record`, `snapshot_artifact`, and `snapshot_event` output with
snapshot ids, hashes, trigger context, receipt refs, artifact refs, restore
metadata, payload summary, and runtime-event admission identity. The daemon
workspace-snapshot surface consumes that output through the mounted
`workspaceRestoreCore`, commits only the Rust-authored snapshot artifact
through Rust Agentgres artifact-state admission, admits only the Rust-authored
snapshot event through Rust Agentgres runtime-event admission, and the
coding-tool invocation surface no longer calls JS snapshot-event authorship or
completes a successful `file.apply_patch` result when the Rust snapshot
record/artifact/event is missing.

Coding-tool workload observation field ownership is now canonical at the Rust
source for the migrated hot path. `coding_tool_workspace.rs` emits snake_case
observations for workspace status, git diff, file inspect, file patch, test run,
and LSP diagnostics, including nested patch changed-file/snapshot drafts and
diagnostics project context. The runtime-daemon Rust-live result wrapper strips
retired camelCase observation keys recursively instead of translating them, and
the coding-tool result summaries/output contracts read only canonical Rust
result fields. Post-edit diagnostics consumes `file.apply_patch.changed_files`
only; retired `changedFiles`/`beforeHash`/`diagnosticsRecommended` patch result
aliases no longer trigger diagnostics repair context construction.

Post-edit diagnostics feedback planning is now a positive Rust daemon-core API.
`plan_post_edit_diagnostics_feedback` owns diagnostics mode normalization,
changed-path selection, repair-policy normalization, workspace snapshot and
rollback refs, auto diagnostics `tool_call_id`, diagnostics rollback repair
context authoring, and the `lsp.diagnostics` request envelope. The JS
diagnostics-feedback surface fails closed without that Rust planner and only
forwards the Rust-authored request to the mounted coding-tool invocation
surface.

Public workspace snapshot and restore read/control APIs are now Rust-owned at
the typed daemon-core workspace restore API boundary.
`projectWorkspaceSnapshotList`, `projectWorkspaceSnapshotContentPackage`,
`previewWorkspaceSnapshotRestore`, and `applyWorkspaceSnapshotRestore` are
typed `daemonCoreWorkspaceRestoreApi` methods backed by Rust
`workspace_restore.rs`; the daemon workspace-snapshot surface calls the mounted
`workspaceRestoreCore` for list/content-package and restore preview/apply
instead of deriving projection truth from JS runtime events or
`codingArtifacts`. Restore preview/apply responses now also carry
Rust-authored restore artifact records and restore runtime-event records; the
JS facade commits only those Rust artifact records through Rust Agentgres
artifact-state admission and admits only those Rust events through Rust
Agentgres runtime-event admission before public restore truth returns.

Public approval request, decision, and revoke controls are now positive Rust
authority calls instead of fail-closed JS facades. The daemon approval surface
uses mounted `approvalStateCore` for all three public control operations and
commits only the Rust-authored run/agent projection through the Agentgres-gated
state persistence hooks. State-update planning now sends runtime `state_dir`;
Rust replays the target run/agent from admitted Agentgres projections, can
resolve the latest run without JS supplying a run id, and rejects retired
`run`/`agent` candidate transport before public control truth can return. The
approval-state JS runner facade, command/env fallback, response normalizer, JS
approval request/decision readback, JS target lookup, runtime-event append, and
camelCase request aliases stay retired.

Public approval request authority is now Rust-issued before request state
planning. Rust `approval.rs` exposes `authorize_approval_request`; the public
request surface calls the typed approval API first, requires a Rust
request-authority record with authority receipt refs and authority hash, and
the Rust request state planner fails closed without that binding before any
Agentgres-gated JS commit can persist. The old one-call request state-update
shape is no longer terminally valid, and `authorize_approval_request` remains
retired from command transport.

Public approval decision/revoke authority is now wallet.network-bound at the
typed Rust daemon-core approval API boundary. Rust `approval.rs` exposes
`authorize_approval_decision`; the public decision/revoke surface calls the typed
approval API before state planning, and every decision outcome now requires a
typed `wallet_approval_grant` artifact. Rust verifies the grant structure,
derives the canonical approval grant artifact hash/ref, emits those bindings in
the authority record/hash, and ignores caller-supplied approval grant-ref strings
for approve, reject, and revoke. The Rust decision/revoke state planners fail
closed without that authority binding before any Agentgres-gated JS commit can
persist. The JS surface no longer treats caller-provided `receipt_refs` or
`authority_grant_refs` as approval authority truth; it forwards only the Rust
authority receipts/hash/grant bindings into the state update. Broader
wallet.network grant issuance and
consumption semantics, approval authority projection/replay, and stable direct
Rust approval protocol/API bindings remain non-terminal beyond the thin JS
protocol-client scaffolding.

Public approval queue/read projection is now Rust-owned at the daemon-core
approval API boundary. Rust `approval.rs` exposes `project_approval_queue`, derives
pending/resolved approval queue records by replaying admitted `agents/*.json`
and `runs/*.json` Agentgres projections from runtime `state_dir`, filters
resolved records unless explicitly requested, rejects JS-supplied
`agent`/`run`/`runs` queue candidate transport, and emits canonical snake_case
request, decision, lease, receipt, and policy refs. The daemon approval surface
exposes `listThreadApprovals()` only as a thin protocol client that forwards
`thread_id`, `include_resolved`, optional heads, and `state_dir`, and
`GET /v1/threads/:thread_id/approvals` now returns the Rust projection instead
of resurrecting JS approval event/readback helpers or candidate collectors.

Slice 1206 retires the approval-state runner facade. The daemon store now
mounts `approvalStateCore` directly; `runtime-approval-state-runner.mjs` and its
tests are deleted, `index.mjs` no longer reads command/env fallback for
approval-state, and the public approval surface consumes the mounted core for
request, decision, revoke, and queue projection. The core builds only canonical
Rust daemon-core approval API requests, requires typed `daemonCoreApprovalApi`,
rejects generic `daemonCoreInvoker` plus retired aliases/options, validates only
the Rust `operation_kind`, and returns the Rust `approval.rs` envelope
without JS synthesis of source, backend, queue counts, authority refs, or state
defaults. Conformance now requires the core mount and the old runner paths to
stay absent, and also requires queue reads to replay via `state_dir` instead of
JS `agent`/`run`/`runs` candidates.

Slice 1207 retires the runtime Agentgres admission runner facade. The daemon
store now mounts `runtimeAgentgresAdmissionCore` directly over typed
`daemonCoreAgentgresApi` methods;
`runtime-agentgres-admission-runner.mjs` and its tests are deleted, command/env
fallback and spawn hooks are gone, and runtime event admission, projection,
replay, thread/turn projection, storage-write admission, and runtime
run/agent/memory/subagent/artifact/model_mount state commits all call the
mounted core. The core sends typed Rust daemon-core Agentgres API requests,
rejects retired compatibility options including generic `daemonCoreInvoker`,
and returns Rust `agentgres_admission.rs`, `agentgres_protocol.rs`,
`runtime_thread_event.rs`, and `coding_tool_event.rs` envelopes without JS
normalization or fallback truth synthesis. Conformance now requires the core
mount, typed API wiring, Rust-envelope passthrough, retired command operations,
and old runner paths to stay absent.

Slice 1208 retires the workspace restore runner facade. The daemon store now
mounts `workspaceRestoreCore` directly; `runtime-workspace-restore-runner.mjs`
and its tests are deleted, command/env fallback and spawn hooks are gone, and
workspace restore apply-policy planning, preview/apply operation planning,
snapshot capture, snapshot list/content-package projection, and restore
preview/apply all call the mounted core. The core builds canonical Rust
daemon-core workspace restore protocol requests, requires typed
`daemonCoreWorkspaceRestoreApi`, rejects generic `daemonCoreInvoker` plus
retired compatibility options and request aliases, and returns Rust
`workspace_restore.rs` envelopes without JS normalization or fallback truth
synthesis. The old Rust workspace restore command operations are retired. The
workspace-snapshot surface now requires Rust `projection`, `restore_preview`,
and `restore_apply` envelopes before committing/admitting artifact or
runtime-event truth. Conformance now requires the core mount, Rust-envelope
passthrough, and old runner paths to stay absent.

Slice 1209 retires the coding-tool approval runner facade. The daemon store now
mounts `codingToolApprovalCore` directly; `runtime-coding-tool-approval-runner.mjs`
and its tests are deleted, command/env fallback and spawn hooks are gone, and
approval manifest planning, approval satisfaction projection, approval
satisfaction planning, and approval block planning all call the mounted core.
The core builds canonical Rust daemon-core approval API requests, requires typed
`daemonCoreApprovalApi`, rejects generic `daemonCoreInvoker` plus retired
compatibility options and request aliases, and returns Rust `approval.rs`
envelopes without JS normalization or fallback truth synthesis. The old Rust
approval command operations are retired. The coding-tool approval policy remains
a Rust-client adapter over that core, while the JS event/lease satisfaction gate,
manifest matcher, and approval-block facade stay retired. Conformance now
requires the core mount, Rust-envelope passthrough, and old runner paths to stay
absent.

Slice 1210 retires the model_mount admission runner facade. `ModelMountingState`
now mounts `modelMountCore` directly; `model-mount-admission-runner.mjs` and its
tests are deleted, the daemon store/service pass only `modelMountCore`, and the
old command/env factory path is gone. Route decision, invocation admission,
provider execution, provider invocation/stream execution, lifecycle/inventory,
instance lifecycle, provider-result admission, artifact-endpoint planning,
storage control, route-control planning, conversation/stream planning, MCP workflow planning, server-control planning, runtime-engine planning, runtime-survey planning, catalog-provider control planning, provider control planning, capability-token control planning, vault control planning, receipt-gate planning, accepted-receipt head/transition planning, and invocation receipt-binding now call typed
`daemonCoreModelMountApi` methods instead of command envelopes. Rust rejects the
retired command operations, dispatch arms, and bridge request/response wrappers
for that family. Backend process/lifecycle and projection
helpers still enter Rust through remaining migration transport. Read-projection now calls
`daemonCoreModelMountApi.planModelMountReadProjection`, backed by
`RuntimeKernelService::plan_model_mount_read_projection`; the old
read-projection command operation, dispatch arm, bridge wrapper, backend/source
marker, and JS command-envelope builder are retired. Catalog-provider control,
provider control,
capability-token control, vault control, and receipt-gate planning now call typed
`daemonCoreModelMountApi` methods backed by Rust `RuntimeKernelService`; the
old command operations, dispatch arms, bridge wrappers, backend markers, and JS
command-envelope builders are retired. The core requires typed
`daemonCoreModelMountApi` for migrated model_mount APIs, rejects retired
`command`, `args`, `env`, and `daemonCoreInvoker` compatibility options, stores
no generic direct-invoker shim, and keeps Rust-owned receipt refs, evidence refs,
process fields, inventory fields, expected heads, binding records, and
projection evidence absent instead of synthesizing JS fallback truth. The old JS
in-flight model invocation coalescing map is also deleted;
migrated invocation calls stay on the Rust provider path instead of minting a JS
`model_invocation_coalesced` receipt. Conformance now requires the old runner
paths and symbols to stay absent, typed API calls to omit `operation`/`backend`,
and the retired command transport to stay rejected.

Slice 1211 moves MCP external-exit wallet, cTEE custody, and containment
authority into Rust daemon-core
planning for the two live migration edges that still sit before actual MCP
transport execution. `plan_mcp_control_agent_state_update` now rejects
`mcp_invoke` and `mcp_live_discovery` without canonical wallet grant refs and
authority receipt refs, cTEE custody refs, and transport containment refs, binds
`wallet.network.mcp_external_exit`, the refs, and an authority hash into the
Rust control record, and marks custody/containment requirements instead of
letting JS mint or default them. The
model_mount `plan_model_mount_mcp_workflow` path applies the same wallet gate to
MCP tool invocation and workflow-node execution before Rust-authored workflow
records can be committed. Conformance now requires the no-authority negative
paths, no-custody/no-containment negative paths, and snake_case protocol
forwarding to remain in place. Live external MCP transport execution and
discovery, broader runtime containment sandboxing, and stable protocol APIs
remain non-terminal.

Slice 1212 retires the remaining JS-authored MCP manager catalog record
builders. `mcp-manager.mjs` no longer exports `normalizeMcpServerRecord()`,
`mcpToolsForServers()`, `mcpResourcesForServers()`, `mcpPromptsForServers()`,
or the JS tool/resource/prompt materializers. The JS manager only reads raw
inline/workspace/global config sources, forwards canonical
`mcp_json.mcp_servers` plus source path/scope/compatibility metadata to Rust
`project_mcp_server_validation_input`, and returns server/tool/resource/prompt
rows from Rust `plan_mcp_manager_catalog_projection`. Agent creation,
agent-scoped MCP status, and catalog projection pass the mounted Rust policy
core into that registry path, so the deleted JS builders cannot be recovered as
a no-invoker fallback. Rust `McpServerValidationInputCore` now owns source
metadata projection for MCP config files and rejects retired camelCase
source/config aliases before public server records can return. This is still
non-terminal because actual Rust MCP transport execution, runtime containment
sandboxing for live backends, command transport, and stable APIs remain open.

Slice 1213 retires the MCP workflow execution `rust_required` placeholder for
the migrated model-mount MCP tool and workflow-node hot paths. Rust
`plan_model_mount_mcp_workflow` now returns admitted execution contracts:
`model_mount.mcp_tool.invoke` emits `transport_execution_status:
"rust_admitted"` with content receipt refs and StepModuleRouter owner while
omitting the retired no-JS/no-command/no-binary-bridge/no-compatibility fallback
proof fields entirely, and
`model_mount.workflow_node.execute` emits the matching `execution_status:
"rust_admitted"` StepModule dispatch contract. The Rust authority hash binds
the transport containment ref alongside wallet grant refs, authority receipt
refs, and cTEE custody refs. The JS model-mount core rejects stale
`rust_required` and fallback-proof MCP workflow execution responses instead of
normalizing them into public truth. Slice 1382 supersedes the tool-invocation
side of this blocker by requiring Rust MCP live backend execution before
model_mount MCP tool truth can commit; live external MCP discovery, runtime
containment for external backends, direct protocol APIs, and command-transport
retirement remain open elsewhere.

Slice 1214 binds the migrated model-mount MCP execution hot paths to
Rust-authored execution/content receipts instead of leaving result truth implied
by the admitted control record. Rust `plan_model_mount_mcp_workflow` now returns
an `ioi.model_mount.mcp_workflow_receipt.v1` receipt for MCP tool invocation and
workflow-node execution, with `rust_daemon_core_receipt_author:
"model_mount.mcp_workflow"`, the workflow/authority hashes, cTEE custody and
transport containment refs, Agentgres operation refs, state roots, and
StepModuleRouter result binding. The JS model-mount state path now requires
`persistRustAuthoredReceiptWithCommit()` for those execution receipts and fails
closed when the Rust receipt or receipt-state commit is absent; store guards
reject direct JS MCP execution receipt appends without the Rust content receipt
and Agentgres/state-root binding. Slice 1238 extends this receipt path with
Rust-materialized protocol result payload hashes and makes the old pending
materialization state fail closed.

Slice 1215 binds runtime MCP live invoke/discovery exits to Rust-authored
runtime receipt-state commits. Rust `plan_mcp_control_agent_state_update` now
returns an `ioi.runtime.mcp-live-exit-receipt.v1` receipt for `mcp_invoke` and
`mcp_live_discovery`, with `rust_daemon_core_receipt_author:
"runtime.mcp_control"`, wallet authority refs, cTEE custody refs, transport
containment refs, before/after agent-state roots, Agentgres operation refs, and
resulting-head binding. The Rust planner adds the receipt id to the returned
agent projection's canonical `receipt_refs`, and the JS MCP control surface now
requires `commitRuntimeReceiptState()` before `writeAgent()` can persist the
live-exit projection. Missing Rust receipt, invalid receipt binding, missing
receipt-state committer, or receipt-state commit without `commit_hash` fails
closed before public live-exit truth can return. The new generic
`commit_runtime_receipt_state` daemon-core operation persists runtime receipts
under `receipts/*.json` through Rust Agentgres storage admission, so JS cannot
substitute direct JSON writes or a model-mount receipt path. This remains
non-terminal until the Rust MCP transport backend materializes real contained
tool/discovery result payloads and Rust replay/projection exposes those payloads
through stable protocol APIs without temporary command transport.

Slice 1216 binds runtime MCP live invoke/discovery exits to Rust-authored
live-result state commits. Rust `plan_mcp_control_agent_state_update` now
returns an `ioi.runtime.mcp-live-result.v1` result record for `mcp_invoke` and
`mcp_live_discovery`, with `rust_daemon_core_result_author:
"runtime.mcp_control"`, the live-exit receipt id, Agentgres operation refs,
before/after agent-state roots, resulting-head binding, and no retired
JS/command/binary-bridge/compatibility fallback proof fields. The Rust
planner adds the result id to the returned agent projection's canonical
`result_refs`, and the JS MCP control surface now requires
`commitRuntimeMcpLiveResultState()` after `commitRuntimeReceiptState()` and
before `writeAgent()` can persist the live-exit projection. Missing Rust result
record, invalid result/receipt/state-root binding, missing result-state
committer, or result-state commit without `commit_hash` fails closed before
public live-exit truth can return. The new
`commit_runtime_mcp_live_result_state` daemon-core operation persists runtime
MCP live-result records under `mcp-live-results/*.json` through Rust Agentgres
storage admission, so JS cannot substitute a live transport result projection.
This intermediate blocker is superseded by the later Rust live backend executor
cuts; remaining runtime MCP work is containment hardening for live backends and
stable protocol APIs that replay/project those Rust records without temporary
command transport.

Slice 1217 binds runtime MCP live-result public return to Rust-owned
Agentgres replay/projection. Rust `McpLiveResultReplayCore` and
`project_mcp_live_result_replay` now read committed runtime MCP live-result
records from `mcp-live-results/*.json` under runtime `state_dir`, filter only
canonical `ioi.runtime.mcp-live-result.v1` records with
`rust_daemon_core_result_author: "runtime.mcp_control"`, required
Agentgres/live-result evidence refs, and no retired JS/command/binary-bridge/
compatibility fallback proof fields, then return
`ioi.runtime.mcp-live-result-replay.v1` with `latest_result`
and a replay hash. The JS MCP control surface now calls
`projectMcpLiveResultReplay()` after `commitRuntimeReceiptState()` and
`commitRuntimeMcpLiveResultState()` and before `writeAgent()`, validates the
replayed result against the Rust receipt/control/state-root binding, and returns
that replayed result instead of the planner's direct `record.result`. Missing
state dir, missing replay API, invalid replay projection, JS-authored result
candidate, or uncommitted result id fails closed before public live-exit truth or
agent truth can return. This remains non-terminal until actual external Rust MCP
backend invocation and discovery execute inside the contained runtime, command
transport is retired for this hot path, and stable IDE/CLI/SDK protocol APIs
consume the Rust replay records directly.

Slice 1218 moves public MCP tool search/fetch projection into Rust daemon-core.
Rust `McpToolSearchProjectionCore` / `McpToolFetchProjectionCore` and
`project_mcp_tool_search_projection` / `project_mcp_tool_fetch_projection` now
derive query/tool/server filtering, stable ordering, catalog summaries,
pagination, fetch `not_found`/`completed` status, routes, and evidence from
Rust `McpManagerCatalogProjectionCore` and
`McpManagerCatalogSummaryProjectionCore`. The runtime MCP catalog surface now
sends canonical `query`, `tool_id`, `server_id`, `thread_id`, `agent_id`,
`state_dir`, and `live_discovery` to Rust, and no longer imports or calls JS
`mcpToolMatchesQuery`, `mcpToolIdentityMatches`, `mcpToolKey`,
`resolveMcpServerRecord`, or `mcpLiveExecutionModeForServer` for public
search/fetch truth. JS maps Rust `not_found` to the route error only. This
remains non-terminal because actual MCP transport execution, payload
materialization, command transport retirement, and stable IDE/CLI/SDK protocol
APIs over Rust projection/replay records still need deeper Rust ownership.

Slice 1219 retires the model_mount accepted-receipt and invocation
receipt-binding command transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountAcceptedReceiptHead`,
`planModelMountAcceptedReceiptTransition`, and
`bindModelMountInvocationReceipt` without `operation` or `backend` fields;
Rust `RuntimeKernelService` exposes the matching direct methods over
`model_mount_receipt.rs`; and command-protocol source absence keeps the retired
`plan_model_mount_accepted_receipt_head`,
`plan_model_mount_accepted_receipt_transition`, and
`bind_model_mount_invocation_receipt` operations. The JS normalizers preserve
Rust daemon-core sources instead of synthesizing command/backend truth, and
conformance now guards the old bridge request/response wrappers, dispatch arms,
source/backend markers, command-envelope builders, and direct-invoker fallback
from returning.

Slice 1220 retires the model_mount tokenizer and required-control command
transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountTokenizerRequired`,
`planModelMountRouteControlRequired`, and `planModelMountTokenizer` without
command-envelope `operation` or `backend` fields; Rust
`RuntimeKernelService` exposes
`plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer`; and command-protocol source absence keeps the retired
`plan_model_mount_tokenizer_required`,
`plan_model_mount_route_control_required`, and
`plan_model_mount_tokenizer` operations. The JS normalizers preserve Rust
daemon-core sources instead of synthesizing tokenizer or required-control
command/backend truth, and conformance now guards the old bridge request/response
wrappers, dispatch arms, source/backend markers, command-envelope builders, and
direct-invoker fallback from returning.

Slice 1221 retires the model_mount conversation/stream command transport.
`ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountConversationState`,
`planModelMountStreamCompletion`, and `planModelMountStreamCancel` without
command-envelope `operation` or `backend` fields; Rust
`RuntimeKernelService` exposes
`plan_model_mount_conversation_state`,
`plan_model_mount_stream_completion`, and `plan_model_mount_stream_cancel`;
and command-protocol source absence keeps the retired
`plan_model_mount_conversation_state`,
`plan_model_mount_stream_completion`, and
`plan_model_mount_stream_cancel` operations. The JS normalizers preserve Rust
daemon-core sources instead of synthesizing conversation/stream command/backend
truth, and conformance guards the old bridge request/response wrappers,
dispatch arms, source/backend markers, command-envelope builders, and
direct-invoker fallback from returning.

Slice 1222 retires the model_mount backend-process/backend-lifecycle planning
command transport. `ModelMountCore` now calls typed
`daemonCoreModelMountApi.planModelMountBackendProcess` and
`planModelMountBackendLifecycle` without command-envelope `operation` or
`backend` fields; Rust `RuntimeKernelService` exposes
`plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle`; and command-protocol source absence keeps
the retired `plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle` operations. The Rust direct API responses
preserve daemon-core sources instead of command/backend markers, JS normalizers
no longer synthesize backend truth, and conformance guards the old bridge
request/response wrappers, dispatch arms, source/backend markers,
command-envelope builders, and direct-invoker fallback from returning. This is
not terminal backend execution ownership: actual process supervision/transport
execution, live external backend process-state supervision, and stable
SDK/IDE/CLI backend APIs remain open.

Coding-tool approval satisfaction projection is now Rust-owned. The daemon
approval core exposes `project_coding_tool_approval_satisfaction`; Rust
`approval.rs` derives the approval request, latest decision or revoke, lease
state, expected head, and state root by replaying admitted `agents/*.json` and
`runs/*.json` projections from runtime `state_dir` before
`plan_coding_tool_approval_satisfaction` evaluates the manifest. The optional
JS store projection callback, projection-context helper, `run`/`agent`
candidate transport, and exported JS manifest matcher are retired, so
approval-required coding-tool execution can no longer recover a parallel JS
truth path for request/decision/lease matching.

Coding-tool budget-block governance is now a positive Rust daemon-core path
instead of a fail-closed JS facade. Rust `policy/context_lifecycle.rs` exposes
`plan_coding_tool_budget_block`, emits the blocked coding-tool result/event
envelope with canonical budget status, policy refs, receipt refs, and
snake_case fields, and the invocation hot path admits that blocked event
through Rust `admit_coding_tool_result_event` before returning the public
policy error. The JS governance surface only forwards canonical request facts
to the Rust planner, strips retired budget-policy aliases, and remains
fail-closed when the planner is absent; it no longer owns budget-block event or
response-truth construction.

Public thread runtime-control state updates are now a positive Rust
daemon-core path. The public mode/model/thinking and generic runtime-control
facades call Rust `plan_thread_control_agent_state_update`, pass canonical
agent/control/event-sequence/model-route facts, require Rust-owned receipt refs,
and persist only the Rust-authored agent projection through the
Agentgres-backed `writeAgent` commit path. The direct JS runtime-control event
append facade remains retired, and model route selection remains a separate
model_mount authority dependency before the Rust thread-control plan is
accepted.

Public run cancellation is now a positive Rust daemon-core path. The run-cancel
surface calls Rust `plan_run_cancel_state_update`, requires the returned
`run.cancel` projection to be canceled and complete with terminal job/run
events, runtime task/job/checklist records, receipts, and artifacts, then
persists only that Rust-authored run through the Agentgres-backed `writeRun`
commit path. Missing planners still fail closed through the Rust
admission-required envelope, and JS run-map mutation plus JS runtime
task/job/checklist, event, receipt, and artifact materialization remain retired.

Public task/job cancellation is now a positive Rust daemon-core path. The
task/job control surface calls Rust `plan_runtime_task_job_cancel_state_update`,
derives only the canonical run id from `task_`/`job_` public ids in JS, requires
the returned `task.cancel` or `job.cancel` projection to match the requested
public id and include canceled task/job/checklist plus run records, terminal
events, receipts, and artifacts, then persists only that Rust-authored run
through the Agentgres-backed `writeRun` commit path. The old `cancelRun`
shortcut, public-id fallback, and JS task/job/checklist/event/receipt/artifact
materialization paths remain retired.

Public task creation is now a positive Rust daemon-core path. The task/job
control surface calls Rust `plan_runtime_task_job_create_state_update`, requires
canonical `agent_id`, gathers only the existing agent, model-route, memory, and
run candidate after the Rust planner boundary exists, and requires Rust-authored
`task.create` task/job/checklist plus run projections before committing only the
returned run through Agentgres-backed `writeRun`. Direct `createAgent`,
`createRun`, JS task/job/checklist projection synthesis, retired request aliases,
and projection mismatch compatibility paths remain retired.

Public task/job read projection is now a positive Rust daemon-core path. The
task/job control surface calls Rust `project_runtime_task_job_projection` for
task/job list and get, JS only supplies runtime `state_dir` plus canonical
`agent_id`, `status`, `task_id`, or `job_id` request facts, and Rust replays
admitted `runs/*.json` Agentgres state before record construction, filtering,
and public-id selection. The task/job surface no longer receives the JS runtime
task/job record builders or `runs` candidate transport, retired `agentId`
aliases stay ignored, and missing or mismatched Rust projections fail closed
instead of falling back to JS readback.

Generic runtime thread-event append is now a positive Rust daemon-core
Agentgres admission path. Runtime events call Rust `admit_runtime_thread_event`,
must carry receipt refs, expected heads, state roots, storage admission, payload
refs, and projection watermarks, and JS may only register the Rust-returned
event in its temporary local replay cache. Synthetic `thread.started` and
run-event projection now call Rust `project_runtime_thread_events`; Rust authors
the projection envelopes from canonical agent/run facts, rejects retired
projection aliases, skips known idempotency keys, admits each projected event
through the same Agentgres admission core, and returns only Rust-admitted events
for local replay registration. Public stream/turn replay readback now calls Rust
`project_runtime_thread_event_replay` with replay kind, cursor, latest seq, and
runtime `state_dir`; Rust reads admitted Agentgres `events/*.jsonl` records,
owns replay selection, canonical cursor evaluation, required Agentgres
admission refs, state/head/watermark projection, and the returned event set,
and rejects caller-supplied replay `events` transport. Public run replay enters
through `eventsForRun`, while the duplicate `replayFromCanonicalState` facade
and JS replay-candidate collector are retired. Public thread/turn projection
records now call Rust
`project_runtime_thread_turn_projection`; Rust owns public thread/turn record
shape, runtime identity fields, projection hashes, and event-derived seq/input/
output fields through typed
`daemonCoreAgentgresApi.projectRuntimeThreadTurnProjection`; JS now sends only
projection kind, thread/run/turn identity, event stream, schema, and runtime
`state_dir`, while Rust replays Agentgres `agents`, `runs`, event, memory, and
subagent records and rejects caller fact transport. Stable
Rust lifecycle projection protocol APIs remain non-terminal beyond that thin JS
protocol-client scaffolding.

This is still not terminal coding-tool migration. Coding-tool artifact draft
materialization now calls Rust `plan_runtime_coding_tool_artifact_drafts`,
receives Rust-authored artifact records, and commits them through Rust
Agentgres artifact-state admission before the daemon updates its temporary read
cache; the old JS artifact draft record materializer remains retired. Artifact
read/retrieve projection now calls Rust
`project_runtime_coding_tool_artifact_read` with runtime `state_dir`, so Rust
owns durable `artifacts/*.json` Agentgres replay, canonical coding-tool artifact
filtering, thread ownership checks, byte-range shaping, result metadata,
receipt refs, available-artifact projection, and retired `artifact_records`
candidate-transport rejection. JS still coordinates snapshot materialization,
diagnostics orchestration, runner transport, and projection adapters around
Rust-owned plans. Diagnostics projection/replay, temporary runner transport,
wallet.network grant issuance semantics, and authority projection/replay still
need direct Rust daemon-core ownership; approval lease authority is now
Rust-owned and no longer comes from a JS helper.

This is still not terminal migration. These runner, gate, coding-tool,
thread-control, run-cancel, task/job create/control/projection,
agent-lifecycle, and subagent propagated-cancel cuts remove command fallback
and duplicate JS truth paths, but many public JS facades still remain
fail-closed protocol scaffolding. Resume with a macro authority cut that
replaces one fail-closed facade family with a positive Rust daemon-core API and
then deletes or demotes the JS facade in the same reviewable move. Public
memory write/edit/delete/policy controls have moved to Rust-owned planning plus
Agentgres memory-state commits. Mutation controls now send runtime `state_dir`;
Rust replays admitted `memory-records/*.json` for edit/delete current-record
truth and `memory-policies/*.json` for policy current truth, and rejects
JS-supplied `current_record`/`current_policy` transport. Status/validation/direct
control-event append now uses Rust memory-control event planning plus Rust runtime-event
admission. Explicit public thread/agent memory list/policy/path/status/validation routes now send
only route-owned thread/agent context, filters, and runtime `state_dir` to Rust
`project_runtime_memory_projection`; Rust replays admitted
`memory-records/*.json` and `memory-policies/*.json`, filters active canonical
records, synthesizes effective policy/path/status/validation truth, and rejects
retired JS projection candidate transport before public read truth can return.
The top-level `/v1/memory*` context-query/body route family, daemon-store
`memoryProjectionForContext`/`memoryStatus`/`validateMemory` helpers, SDK global
`getMemoryStatus()`/`validateMemory()` clients, and their context-query input
types are retired; memory status/validation clients now enter through explicit
thread/agent daemon protocol routes over the Rust-owned projection/control
records.
The remaining memory blockers are wallet/policy authority, cTEE private-memory
custody, direct memory admission/storage APIs, richer durable replay/projection,
and stable IDE memory APIs.
Public approval queue/read projection now sends runtime `state_dir`; Rust
replays admitted `agents/*.json` and `runs/*.json` Agentgres projections and
rejects JS `agent`/`run`/`runs` queue candidate transport before queue truth can
return. Public approval request/decision/revoke state updates now use the same
runtime `state_dir` replay source and reject JS `agent`/`run` candidate
transport before target truth can return; the public JS surface no longer reads
`agentForThread`, `getRun`, `listRuns`, or `runs.get` for approval control.
Coding-tool approval satisfaction projection also uses runtime `state_dir`
replay and rejects JS `agent`/`run` candidate transport before
request/decision/lease truth can return. The remaining approval blockers are
richer approval authority projection/replay storage, grant issuance
semantics, and stable protocol APIs.
Runtime MCP registry/control state has moved from the fail-closed JS mutation
facade into Rust-owned `plan_mcp_control_agent_state_update` planning plus
Agentgres-backed `writeAgent` commits. Import/add/remove/enable/disable,
status-record, validation, and direct control-event state paths now require a
Rust-authored control envelope, registry count/hash, and agent projection before
persistence; live MCP invoke/discovery exits now also require Rust-authored
`mcp_invoke` or `mcp_live_discovery` transport-admission controls with
canonical wallet grant refs, authority receipt refs,
`wallet.network.mcp_external_exit`, an authority hash, cTEE custody refs, and
transport containment refs plus Rust-authored
`ioi.runtime.mcp-live-exit-receipt.v1` receipts and
`ioi.runtime.mcp-live-result.v1` live-result records before Agentgres-backed
receipt, result, and agent commits. The JS surface only forwards canonical
request/server/tool/transport/authority facts plus `agent_id` and runtime
`state_dir`, then acts as the
`commitRuntimeReceiptState()`/`commitRuntimeMcpLiveResultState()`/
`projectMcpLiveResultReplay()`/`writeAgent()` adapter for Rust-authored
live-exit truth;
Rust replays the admitted `agents/*.json` projection before planning registry
or transport-admission state and rejects JS-supplied `agent` candidate
transport. MCP manager config-source projection is also Rust-authored:
`mcp-manager.mjs` only forwards raw canonical config inputs plus source
metadata to Rust validation-input and catalog-projection cores, while deleted
JS server/tool/resource/prompt builders cannot return as fallback truth. Public
MCP tool search/fetch now calls Rust
`projectMcpToolSearchProjection()`/`projectMcpToolFetchProjection()` for
query/tool/server filtering, stable ordering, catalog summaries, pagination,
and fetch `not_found`/`completed` status; JS only maps Rust `not_found` to the
route error. Direct registry mutation, JS agent lookup, event append,
`agents.set`, JS MCP transport execution, JS MCP catalog row/search/fetch
building, and old compatibility aliases stay retired. MCP serve `tools/call`
now requires Rust daemon-core
`plan_runtime_mcp_serve_tool_call` for request-envelope authorship before
routing allowed served coding-tool requests through the Rust-owned coding-tool
invocation surface, then requires Rust daemon-core
`project_runtime_mcp_serve_tool_result` to author the MCP result envelope,
`content`, `structuredContent`, canonical `event_id`, receipt/policy/artifact
refs, and `isError` state before JSON-RPC wrapping. JS no longer derives served
tool-call ids, idempotency keys, workflow ids, `mcp_serve_request`, result text,
event refs, or result error state; the old `mcpServeToolCallResult` helper is
retired and the path fails closed instead of preserving a JS envelope/result
facade. Slice 1236 moves MCP serve result public truth behind Rust-authored
Agentgres live-result replay: the Rust projector emits a materialized
`ioi.runtime.mcp-live-result.v1` record whose payload contains the protocol
result, whose details declare `runtime.mcp_serve` authorship, receipt binding,
StepModuleRouter/Rust coding-tool invocation ownership, and no retired
JS/command/binary-bridge/compatibility fallback proof fields. The MCP serve
adapter now refuses to invoke the tool unless `commitRuntimeMcpLiveResultState`,
runtime `stateDir`, and `projectMcpLiveResultReplay` are available, commits the
Rust live-result record under Agentgres, and returns only the replayed protocol
payload. Rust `McpLiveResultReplayCore` accepts `runtime.mcp_serve` as a Rust
author while still filtering JS-authored live-result candidates. The runtime MCP
control/catalog direct API cut then removes temporary
command transport for MCP control state-update, live-result replay, server
validation, validation-input projection, manager validation/status/catalog/
catalog-summary projection, and tool search/fetch projection:
`RuntimeContextPolicyCore` now requires typed `daemonCoreMcpApi` methods,
`mcp-manager.mjs` no longer passes a generic command invoker or
`daemonCoreApi.mcp` compatibility mount, `policy/mcp_memory.rs` no longer
exports MCP command-response wrappers or bridge request structs, and
command-protocol source absence keeps the retired MCP command operations out of
daemon-core transport. Slice 1224
then retires the MCP serve command transport: `RuntimeContextPolicyCore` calls
typed `daemonCoreMcpApi.planRuntimeMcpServeToolCall` and
`daemonCoreMcpApi.projectRuntimeMcpServeToolResult`, Rust
`RuntimeKernelService` exposes the matching positive methods, the old
`plan_runtime_mcp_serve_tool_call` and
`project_runtime_mcp_serve_tool_result` command operations, dispatch arms,
response wrappers, `RuntimeMcpServeCommandError`, command source markers, and JS
command-envelope fields are absent, and conformance requires command-protocol
rejection for both retired operations. Runtime containment sandboxing for live
backend discovery/serve flows, broader serve admission, and stable protocol APIs
over Rust replay records remain non-terminal.
Model-mount MCP workflow control has a matching typed Rust positive boundary:
`daemonCoreModelMountApi.planModelMountMcpWorkflow` now calls Rust
`RuntimeKernel::plan_model_mount_mcp_workflow` for import, ephemeral
registration, MCP tool invocation, and workflow-node execution record planning;
the old `plan_model_mount_mcp_workflow` command operation, dispatch arm, bridge
wrapper, command-envelope builder, and backend tag are retired. Tool invocation
and workflow-node execution external exits now require Rust-enforced wallet
grant refs, authority receipt refs, cTEE custody refs, and transport containment
refs before planning/commit, bind those refs to the workflow authority hash and
committed control details, and fail closed without JS no-authority, no-custody,
or no-containment compatibility. Tool invocation and workflow-node execution
also return admitted Rust execution/StepModule dispatch contracts instead of the
retired `rust_required` placeholder response, and the JS model-mount core fails
closed on stale placeholder or pending-materialization responses before public
truth can return. Those execution ops now also require Rust-authored MCP
execution/content receipts, materialized protocol result payload hashes, and Rust
Agentgres receipt-state commit before route truth returns, so JS cannot invent
the content receipt, StepModule result binding, or result envelope locally. Rust
`mcp_servers` read projection replays admitted `mcp-servers` records for public
server list readback. Slice 1382 adds the terminal MCP tool-invocation cut:
`invokeMcpTool()` now requires `contextPolicyCore.executeRuntimeMcpLiveBackend`
over the Rust `ioi.runtime.mcp-backend-execution.v1` contract, canonical
`thread_id` / `agent_id`, and `workload_spec` before model_mount record or
receipt truth can commit. Missing executor, missing backend contract, or missing
live result fails closed with no Agentgres model_mount record commit, and the
committed response carries `runtime_mcp_live_backend_rust_driver_executed`
evidence plus the Rust driver-result hash. The JS surface remains only a
canonical request client plus record/receipt-state commit adapter; JS MCP receipt
synthesis, server-map projection, route tests, receipt-gate dispatch, model
invocation, and plan-only tool-result success stay retired for this family while
live external MCP discovery, broader runtime containment sandboxing, and stable
protocol APIs remain the terminal blockers.
Workflow-edit proposal/apply controls have also moved to Rust-owned event
planning plus Rust runtime-event admission; the remaining workflow-edit blockers
are wallet approval authority, workflow mutation custody, durable
projection/replay, ArtifactRef/PayloadRef binding where needed, command-transport
retirement, and stable protocol APIs.
Diagnostics repair policy projection, decision execution, direct decision-event
append, and decision resolution have moved to Rust-owned projection/event
planning plus Rust runtime-event admission, and diagnostics operator override
execution now uses Rust state-update planning plus Rust Agentgres run-state
admission with Rust-derived operator override approval state instead of JS
verdict transport. Approval-required diagnostics operator overrides now also
require wallet.network grant and authority receipt refs in Rust, bind a
Rust-authored override authority hash into the operator control projection, and
reject retired JS authority transport; direct operator-override event append
uses the same Rust wallet authority gate before runtime-event admission.
Diagnostics repair retry-turn creation now uses Rust
`plan_runtime_diagnostics_repair_retry_run` for retry run-create request
authorship before Rust-owned run-create state update and Rust diagnostics repair
event planning/admission; direct retry-event append still uses Rust diagnostics
repair event planning/admission.
Diagnostics repair policy projection now replays admitted Agentgres runtime
events from runtime `state_dir` instead of accepting JS policy-input candidates.
The remaining diagnostics repair blockers are broader orchestration, durable
projection/replay, receipt/state-root binding,
and stable protocol APIs.
Run-level coding-tool budget recovery retry completion has moved from the
fail-closed JS control facade to Rust `plan_coding_tool_budget_recovery_state_update`
plus Agentgres-backed run-state commit, and budget recovery `request_approval`
and `approve_override` now move through Rust `plan_coding_tool_budget_recovery_control`.
The public route now accepts these controls only when Rust returns a complete
operator control and run projection; override issuance additionally requires
wallet.network grant and authority receipt refs and carries a Rust-authored
authority hash. The standalone JS budget-recovery policy/result helper and the
old admission-required command remain retired. This remains non-terminal because
retry-event materialization, durable replay/projection, command-transport
retirement, and stable SDK/IDE/CLI APIs still need direct Rust ownership.
Managed-session inspection/control has moved from a fail-closed public facade to
Rust daemon-core projection/control planning plus Rust-authored runtime-event
admission. Inspection now sends runtime `state_dir`, and Rust replays admitted
`events/*.jsonl` records instead of accepting JS projection candidates; control
now also sends runtime `state_dir`, Rust replays the selected current session,
and JS control candidates are rejected. The remaining managed-session blockers
are durable session record storage beyond runtime-event replay, wallet/cTEE
session authority, and stable protocol APIs.
Workspace-change inspection/control has moved from a fail-closed public facade
to Rust daemon-core projection/control planning plus Rust-authored runtime-event
admission. Inspection now sends runtime `state_dir`, and Rust replays admitted
`events/*.jsonl` records instead of accepting JS projection candidates; control
now also sends runtime `state_dir`, Rust replays the selected current change,
and JS control candidates are rejected. The remaining workspace-change blockers
are durable workspace-change record storage beyond runtime-event replay,
wallet/workspace rollback authority, and stable
protocol APIs.
Model-mount provider lifecycle has moved from fail-closed JS public
health/start/stop facades to Rust `plan_model_mount_provider_lifecycle` plus
Rust Agentgres model_mount record-state commit. Migrated local/fixture,
native-local, and hosted/custom metadata health/start/stop now receive
Rust-authored `model-provider-lifecycle-controls` records with lifecycle
hash/evidence, operation kind, and `model_mount.provider_lifecycle` boundary,
then require Rust Agentgres commit before returning public lifecycle truth. They
still avoid JS driver execution, lifecycle receipt creation, provider-map
mutation, projection writes, JS endpoint-map subject selection, and JS-hosted
transport execution; provider lifecycle health/start/stop now derive implicit
endpoint/model subjects from the Rust `endpoints` read-projection list instead
of `state.endpoints`, so map-only endpoint rows cannot become lifecycle request
truth before Rust planning; hosted/custom
records carry Rust-contained metadata transport contracts with
`rust_hosted_provider_metadata_transport_materialized`,
`ctee_hosted_provider_secret_not_exposed`, and
`wallet_network_provider_transport_authority_bound` evidence while omitting
retired JS/command/binary-bridge/compatibility fallback proof fields. Public
provider-health list/latest projections now replay admitted
`model-provider-lifecycle-controls/*.json` records in Rust and ignore stale
`provider_health` receipts or JS telemetry inputs. This remains non-terminal
because live external hosted API/model payload execution, deeper
receipt/state-root binding, and stable protocol APIs remain open.
Public model artifact import and endpoint mount/unmount have moved from the
fail-closed artifact/endpoint JS facade to typed
`daemonCoreModelMountApi.planModelMountArtifactEndpoint`, backed by Rust
`RuntimeKernelService::plan_model_mount_artifact_endpoint`, plus Rust
Agentgres model_mount record-state commit. `importModel()`, `mountEndpoint()`,
and `unmountEndpoint()` now receive Rust-authored `model-artifacts` or
`model-endpoints` records with artifact/endpoint hashes, authority hashes,
wallet/cTEE boundary facts, and Agentgres artifact/endpoint truth evidence, then
require Rust commit before returning public truth. The old
`plan_model_mount_artifact_endpoint` command operation, command-dispatch arm,
bridge request/response wrapper, backend marker, and JS command-envelope builder
are retired. They no longer preserve JS artifact/endpoint map mutation, JS
lifecycle receipt synthesis, `writeMap("model-artifacts")`,
`writeMap("model-endpoints")`, local materialization, or no-commit planner
success as compatibility paths. This has since advanced on the read side: public
`listArtifacts()` and `listEndpoints()` now call Rust read-projection kinds over
runtime `state_dir`; Rust replays admitted `model-artifacts/*.json` and
`model-endpoints/*.json` artifact-endpoint records, merges them with
provider-inventory and route endpoint-resolution materializations, applies Rust
unmount records as endpoint removal, and filters JS-authored artifact/endpoint
truth. This remains non-terminal because hosted/provider endpoint
discovery/materialization, deeper receipt/state-root binding, and stable
protocol APIs still need direct Rust ownership.
Public model storage and catalog/download mutations have moved from fail-closed
JS facades to typed `daemonCoreModelMountApi.planModelMountStorageControl`,
backed by Rust `RuntimeKernel::plan_model_mount_storage_control`, plus Rust
Agentgres model_mount record-state commit. `catalogImportUrl()`,
`downloadModel()`, `cancelDownload()`, `deleteModelArtifact()`, and
`cleanupModelStorage()` now receive Rust-authored `model-catalog-imports`,
`model-downloads`, or `model-storage-controls` records with storage/download
evidence, authority hashes, wallet/cTEE boundary facts, and Agentgres truth
evidence, then require Rust commit before returning public truth. They no longer
preserve the storage-control command-envelope builder/operation, bridge response
wrapper, `daemonCoreApi` compatibility mount, JS catalog/download/storage
lifecycle receipts, JS download/artifact map mutation, `writeMap()` storage
truth, fixture/live network materialization, filesystem mutation, or no-commit
planner success as compatibility paths. `storageSummary()`, `listDownloads()`,
and `downloadStatus()` now call Rust model_mount read projection over runtime
`state_dir`, replay admitted storage-control records from `model-catalog-imports`,
`model-downloads`, and `model-storage-controls`, and filter out JS-authored
storage/download truth. Richer filesystem custody, richer catalog/download
materialization, and stable protocol APIs remain non-terminal.
Public provider inventory for migrated fixture/local-folder, native-local, and
hosted metadata providers has moved from fail-closed JS list facades to the Rust
`plan_model_mount_provider_inventory` planner. `listProviderModels()` and
`listProviderLoaded()` now require Rust inventory hash/evidence/action/status
envelopes, receive Rust-authored `model-provider-inventory` records, and commit
only those records through Rust Agentgres model_mount record-state admission
before inventory truth can return. Hosted/nonlocal provider inventory uses the
Rust `rust_model_mount_hosted_provider_inventory` metadata backend, records only
canonical provider metadata/item refs, carries a Rust-contained metadata
transport contract with `rust_materialized` execution status, cTEE
no-plaintext custody evidence, wallet.network transport authority evidence, and
no retired JS/command/binary-bridge/compatibility fallback proof fields, and still
avoids JS driver/network execution. `providerInventoryRecords()` now
calls Rust read-projection kind `provider_inventory_records` with runtime
`state_dir`; Rust replays persisted `model-provider-inventory/*.json` Agentgres
records and filters public truth to Rust-authored provider inventory records.
Migrated provider inventory no longer uses JS driver execution, JS inventory
receipts, local artifact/instance fallback reads, artifact or instance map
mutation, or no-commit planner success.
Public model-mount server-control start/stop/restart/write, operation
recording, and log append have moved from the fail-closed required-record facade
to typed `daemonCoreModelMountApi.planModelMountServerControl`, backed by Rust
`RuntimeKernel::plan_model_mount_server_control`, plus Rust Agentgres
model_mount record-state admission. The old
`plan_model_mount_server_control` command operation, command-dispatch arm,
bridge request/response wrapper, backend marker, and JS command-envelope builder
are retired and guarded by conformance. Migrated server-control mutation methods
receive Rust-authored `model-server-controls` records, commit only those
records, and return Rust public responses with JS state writes, JS log writes,
and JS transport execution marked false. Dedicated `serverStatus()` now calls
Rust read-projection kind `server_status` with empty JS request state plus
runtime `state_dir`; Rust replays admitted `model-server-controls/*.json`,
filters JS-authored server controls, and materializes server status, last
operation, last receipt, topology counts, and backend-state counts from
Rust-owned records. `serverLogs()`, `serverEvents()`, and `serverLogRecords()`
now call Rust read-projection kinds `server_logs`, `server_events`, and
`server_log_records` with canonical `server_log_query` plus runtime `state_dir`;
Rust replays admitted `model-server-controls/*.json`, filters JS-authored
controls and retired read-as-mutation `logs_read`/`events_read`/`log_projection`
records, and returns redacted log/event projections without committing
server-control truth for reads. This remains non-terminal because actual
process supervision, transport execution, and stable server-control protocol
APIs still need direct Rust ownership.
Provider-inventory topology and catalog materialization now replays that same
admitted Agentgres truth in Rust. `listArtifacts()`, `listProductArtifacts()`,
`listProviders()`, `runtimeModelCatalogList()`, and `openAiModelList()` call
Rust read-projection kinds with runtime `state_dir`; Rust filters out
JS-authored inventory, materializes only Rust fixture/native-local
provider/artifact/runtime-catalog/OpenAI-list records, and the dedicated JS
request state stays empty so JS topology maps cannot return as provider or
catalog truth. Hosted/provider endpoint discovery and materialization remain
open because current provider inventory records do not yet carry hosted
endpoint truth; public endpoint-list truth is now Rust-owned from route-control
endpoint-resolution replay.
Public catalog search now consumes that Rust-owned inventory truth through Rust
read-projection kind `catalog_search`. `catalogSearch()` sends only canonical
query facts plus runtime `state_dir`; Rust replays admitted
`model-provider-inventory/*.json` `list_models` records, filters out JS-authored
inventory and loaded-instance inventory, and returns Rust-authored catalog
search entries bound to provider-inventory record ids and inventory hashes before
JS provider-port iteration, JS result aggregation, entry enrichment, or
`lastCatalogSearch` writes can return.
Public `catalogStatus()` now consumes the same Rust-owned inventory truth
through Rust read-projection kind `catalog_status`. `catalogStatus()` sends an
empty request state plus runtime `state_dir`; Rust replays admitted
`model-provider-inventory/*.json` records, filters out JS-authored inventory,
and returns catalog provider status, storage status, last-search summary, and
result rows with catalog-status evidence. JS `catalog_status_input`, provider
port iteration, storage summarization, `lastCatalogSearch` readback, and status
aggregation stay retired.
Live external hosted catalog API execution and dynamic hosted catalog
materialization remain non-terminal, but the public hosted inventory facade no
longer fails closed, returns the retired hosted-transport-not-executed marker, or
returns through JS driver execution. Public
provider upsert now moves through Rust daemon-core
`plan_model_mount_provider_control`: the mounted daemon facade sends canonical
provider facts, never resolves vault material, receives a Rust-authored
`model-providers` record with provider-control and authority hashes,
wallet.network/cTEE no-plaintext custody facts, and Agentgres provider-control
truth evidence, then commits only that record through Rust Agentgres
model_mount record-state admission before returning public provider truth. The
old fail-closed provider-upsert JS facade, provider-map mutation,
`writeMap("model-providers")`, JS vault resolution, plaintext material
readback, and no-commit success remain retired. Provider-control replay for
provider lookup now lives in the Rust `providers` read-projection kind: Rust
replays admitted `model-providers/*.json` records, filters JS-authored provider
truth, and the mounted provider accessor consumes that projection instead of
`state.providers` map truth. Hosted/provider transports, hosted/provider
endpoint discovery/materialization, and stable
direct Rust/Agentgres APIs remain non-terminal.
Public `listInstances()` now calls Rust read-projection kind
`instances` with runtime `state_dir`; Rust replays persisted
`model-instances/*.json` Agentgres records, filters to Rust-authored
instance-lifecycle records with lifecycle hashes and Agentgres registry
evidence, and keeps JS instance maps out of public-list request truth. Public
`listRoutes()` now calls Rust read-projection kind `routes` with runtime
`state_dir`; Rust replays persisted `model-routes/*.json` Agentgres records,
filters to Rust-authored route-control records with route-control evidence and
receipt refs, and keeps JS route maps out of public-list request truth. This is
still non-terminal until hosted provider transports, hosted/provider endpoint
discovery/materialization, richer hosted catalog materialization, deeper Agentgres receipt/state-root
binding beyond record-state commit, and stable
protocol APIs are Rust-owned.
Public model route write/test has moved from the fail-closed route-control JS
facade to typed `daemonCoreModelMountApi.planModelMountRouteControl`, backed by
Rust `RuntimeKernelService::plan_model_mount_route_control`, plus Rust Agentgres
model_mount record-state commits. Mounted route-selection and explicit-model
endpoint resolution now use the same positive Rust route-control planner,
commit only Rust-authored route-selection or endpoint-resolution records, and route
selection reuses Rust model_mount route-decision admission plus the
Rust-authored accepted route-selection receipt before JS sees a selected
endpoint. Public route write/test no longer repopulates `state.routes` or sends
JS route-map `current_route` candidates into Rust; mounted route-selection now
feeds Rust candidate routes, endpoints, and providers from the Rust
read-projection list APIs instead of `this.routes`, `state.endpoints`, or
`state.providers` maps. Runtime explicit/run-override model-route selection now forwards
canonical runtime model-route requests through that Rust-owned route-control
client and returns only the Rust-authored route decision, receipt, and
route-control refs. Public `listRoutes()` now replays persisted
`model-routes/*.json` Agentgres records through Rust read-projection kind
`routes` and emits only Rust-authored route-control records; JS route maps stay
out of the dedicated request state. Public `modelRouteDecisions()` now replays
persisted `model-route-selections/*.json` Agentgres records through Rust
read-projection kind `model_route_decisions`, filters to Rust-authored
route-selection records with route-control evidence and accepted-receipt
binding, and keeps JS receipt arrays out of route-decision request truth.
Public `modelRouteEndpointResolutions()` now replays
`model-route-endpoint-resolutions/*.json` records through Rust
`model_route_endpoint_resolutions` and filters endpoint-resolution truth to
Rust-authored route-control records. Invocation route selection, deeper
wallet/cTEE route authority policy, and direct stable protocol APIs remain
non-terminal.
The old `plan_model_mount_route_control` command operation, Rust dispatch arm,
bridge response wrapper, backend marker, and JS command-envelope builder are
retired for these route-control hot paths; conformance now guards the typed API
and the retired command transport.
Public `listEndpoints()` now replays the same admitted
`model-route-endpoint-resolutions/*.json` Agentgres records through Rust
read-projection kind `endpoints`, materializes canonical endpoint records with
snake_case endpoint fields, filters out JS-authored endpoint-resolution records,
and keeps JS endpoint maps out of public-list request truth.
Public `listInstances()` now calls Rust read-projection kind `instances` with runtime
`state_dir`, replays persisted `model-instances/*.json` Agentgres records,
and emits only Rust-authored instance lifecycle records with lifecycle hashes
and Agentgres registry evidence. The dedicated instance-list request state
remains empty, so JS instance maps cannot return as public topology truth.
deeper receipt/state-root binding, hosted/provider
transports, hosted/provider endpoint discovery/materialization, richer hosted
catalog materialization, stable route/instance APIs, and stable protocol APIs
remain required.
The mounted model_mount topology accessors now consume those Rust read
projections on the daemon hot path: `endpoint()`, `route()`, `instance()`,
`getModel()`, provider-direct mount lookup, model-id endpoint resolution, and
loaded-instance reuse call the Rust-owned `endpoints`, `routes`, `instances`,
and `artifacts` projection lists instead of reading JS topology maps as
accepted truth. Map-only endpoint, route, instance, or artifact cache rows now
fail not-found at the accessor boundary, while provider-direct artifact
creation still fails closed before JS mutation and load fallback enters the
Rust-planned mount/load surfaces.
Loaded-instance maintenance selection now follows the same boundary: idle
eviction, duplicate coalescing, and explicit supersede enumerate Rust
`instances` projection rows, enrich missing endpoint/provider facts from Rust
`endpoints` and `providers` projections, and leave map-only JS instance,
endpoint, or provider cache rows unable to trigger or shape lifecycle planning.
Public catalog-provider configuration, private runtime material, and OAuth
control now move through Rust daemon-core `plan_model_mount_catalog_provider_control`.
`listCatalogProviderConfigs()`, `getCatalogProviderConfig()`,
`configureCatalogProvider()`, `catalogProviderConfig()`,
`catalogProviderRuntimeMaterial()`, and OAuth start/callback/exchange/refresh/
revoke each receive a Rust-authored catalog-provider-control record, commit it
through Agentgres model_mount record-state admission, and return the committed
Rust response envelope. JS no longer executes OAuth credential helpers, resolves
catalog-provider vault refs, reads config/runtime-material maps as accepted
truth, writes OAuth/session/provider maps, or returns plaintext catalog-provider
material for those public control edges. Auth-header materialization, richer
hosted catalog transport, and stable protocol APIs remain required; the
catalog-provider-control command transport is retired.
Public model conversation-state writes and native stream-completion
finalization now move through Rust daemon-core model_mount planners.
`recordConversationState()` calls typed
`daemonCoreModelMountApi.planModelMountConversationState`, backed by
`RuntimeKernelService::plan_model_mount_conversation_state`, and commits only
the Rust-authored `model-conversations` record through Rust Agentgres
record-state admission before updating the local continuation cache.
`recordModelStreamCompleted()` calls typed
`daemonCoreModelMountApi.planModelMountStreamCompletion`, backed by
`RuntimeKernelService::plan_model_mount_stream_completion`, commits only the
Rust-authored conversation record, and persists only the Rust-authored
`model_invocation_stream_completed` receipt carrying
receipt_binder, accepted-receipt append, StepModule result, Agentgres
operation/state-root/resulting-head bindings, and conversation/stream hashes.
JS conversation record synthesis, JS stream-completion receipt synthesis, JS
receipt-binding construction, direct
`state.receipt("model_invocation_stream_completed")`, and
`writeMap("model-conversations")` remain retired. Public
`listConversations()` now calls Rust read-projection kind
`model_conversation_states` with the runtime `state_dir`; Rust replays
persisted `model-conversations/*.json` Agentgres records and emits only
Rust-authored model conversation records carrying conversation hashes, Rust
conversation/stream evidence, and Agentgres conversation-truth evidence. The
old fail-closed JS list facade and public-list `conversation_states` request
input are deleted. Slice 1221 later retired conversation/stream command
transport by moving conversation-state, stream-completion, and stream-cancel
planning to typed `daemonCoreModelMountApi` methods backed by
`RuntimeKernelService`. This remains non-terminal because live hosted stream
completion/finalization materialization, deeper wallet/cTEE conversation
authority, and stable IDE/CLI/SDK APIs still need direct Rust ownership.

Model-mount route-decision admission now uses the typed Rust daemon-core
`daemonCoreModelMountApi.admitModelMountRouteDecision` surface instead of the
generic command-envelope transport. The deleted command-protocol source plus
conformance source scans keep the old `admit_model_mount_route_decision`
command operation absent, `command_dispatch.rs` has
no route-decision arm, and the route-decision bridge request/response helper is
deleted from `model_mount/admission.rs`. The mounted JS model-mount core fails
closed without the typed API and no longer sends `operation` or `backend` fields
for route-decision admission. This retires the route-decision command transport
cut only; later model_mount typed API cuts also retired command transport for
invocation admission, provider-execution admission, provider invocation/stream
execution, provider lifecycle/inventory, instance lifecycle, provider-result
admission, backend-process planning, backend-lifecycle planning,
artifact-endpoint planning, storage control, route-control planning, MCP
workflow planning, server-control planning, read-projection planning, and
conversation/stream planning. Remaining model_mount projection migration,
hosted/provider transport, hosted provider auth materialization, invocation
authority, and remaining non-OAuth cache scaffolding still need direct Rust
daemon-core protocol/API ownership; the read-projection, accepted-receipt,
invocation receipt-binding, tokenizer/required-control, conversation/stream,
backend-process, backend-lifecycle,
catalog-provider/provider/capability-token/vault/receipt-gate command
transports are retired.

Backend-process/backend-lifecycle planning also now uses typed
`daemonCoreModelMountApi.planModelMountBackendProcess` and
`planModelMountBackendLifecycle`, backed by Rust
`RuntimeKernelService::plan_model_mount_backend_process` and
`plan_model_mount_backend_lifecycle`, and the old command operations, dispatch
arms, bridge request wrappers, command source/backend markers, and JS command
envelopes are retired.

Model-mount backend registry lookup now consumes Rust read-projection kind
`backends` through `ModelMountingState.backendRegistry()` and the internal
`backend()` accessor. The old JS backend-registry overlay export that merged
derived backend defaults, `state.backends`, and process snapshots is deleted, so
public APIs and internal process-planning preflight no longer have a duplicate
JS backend truth path. Slice 1266 additionally deletes the mounted
`deriveBackendRegistry()` and `seedBackends()` methods, removes the
`backendRegistryRecords()` JS default-record factory, and stops loading the
retired `model-backends` local map. This remains non-terminal because actual
backend process supervision/transport execution, richer backend process-state
materialization, stable SDK/IDE/CLI APIs still need direct Rust ownership.

Slice 1223 retires the admission-required command transport for workflow-edit,
diagnostics-repair, thread-turn, and lifecycle required-boundary refusals.
`RuntimeContextPolicyCore` now calls typed `daemonCoreRuntimeControlApi`
methods for workflow-edit and diagnostics-repair admission-required records and
typed `daemonCoreThreadLifecycleApi` methods for thread-turn and lifecycle
admission-required records. Rust `RuntimeKernelService` exposes positive direct
methods for the lifecycle admission-required planners, the old bridge request
structs and command-response wrappers are deleted, `command_dispatch.rs` has no
arms for the retired operations, and command-protocol source absence keeps
`plan_workflow_edit_admission_required`,
`plan_diagnostics_repair_admission_required`,
`plan_thread_turn_admission_required`, and
`plan_lifecycle_admission_required` absent as command operations. Conformance
now guards the typed API calls, direct Rust records, and retired command
operations so this family cannot return through JS authority, a command-env
fallback, or the binary bridge command path. This remains non-terminal only
because other route families, especially remaining MCP transport/materialization,
memory custody/replay, and model_mount materialization/protocol work, still need
direct Rust daemon-core ownership.

Slice 1224 retires the MCP serve `tools/call` command transport. MCP serve
planning and result projection now call typed `daemonCoreMcpApi` methods instead
of `evaluateRawPolicy`, backed by Rust
`RuntimeKernelService::plan_runtime_mcp_serve_tool_call` and
`RuntimeKernelService::project_runtime_mcp_serve_tool_result`.
Command-protocol source absence keeps `plan_runtime_mcp_serve_tool_call` and
`project_runtime_mcp_serve_tool_result` absent as command operations,
`command_dispatch.rs` is deleted, the Rust response wrappers and
`RuntimeMcpServeCommandError` are deleted, and JS no longer sends command
`operation`/`backend` envelopes or command-source markers for the MCP serve hot
path. Slice 1236 follows by committing and replaying the Rust-authored MCP serve
live-result record before JSON-RPC return. Conformance now guards the typed API,
direct Rust records, retired command transport, live-result commit/replay
boundary, and source-scan blockers. This remains non-terminal because actual
external Rust MCP transport execution, runtime containment for live backends,
and stable IDE/CLI/SDK protocol APIs still need deeper Rust daemon-core
ownership.

Slice 1225 retires the public runtime projection family command transport for
skill/hook registry, repository workflow, runtime tool catalog, and runtime
lifecycle projections. `RuntimeContextPolicyCore` now calls typed
`daemonCoreRuntimeProjectionApi.projectSkillHookRegistry`,
`projectRepositoryWorkflow`, `projectRuntimeToolCatalog`, and
`projectRuntimeLifecycle` instead of the generic command-envelope
`evaluateRawPolicy` path. Rust `RuntimeKernelService` exposes the corresponding
direct projection methods, command-protocol source absence keeps the old
`project_skill_hook_registry`, `project_repository_workflow`,
`project_runtime_tool_catalog`, and `project_runtime_lifecycle` operations absent,
`command_dispatch.rs` is deleted, and the Rust command-response
wrappers/source markers are deleted. Conformance now guards the typed API,
direct Rust records, retired command operations, missing dispatch wrappers, and
source-scan blockers. The skill/hook projection contract no longer carries the
remaining command-shaped `operation` field: JS sends only `operation_kind`, Rust
serializes no `operation`, and the JS normalizer drops stale `operation` fields
instead of preserving a compatibility path. This remains non-terminal because
durable Rust storage/replay for catalog, repository workflow, lifecycle/run-read, and
doctor/readiness projections plus stable IDE/CLI/SDK protocol APIs still need
deeper Rust daemon-core ownership.

Slice 1226 retires the runtime compositor/task-job command transport family.
Task/job create/cancel state planning, task/job read projection, workflow-edit
control, managed-session projection/control, workspace-change
projection/control, thread-fork control, conversation-artifact
projection/control, and subagent projection/control now enter Rust through typed
`daemonCoreRuntimeControlApi` or `daemonCoreRuntimeProjectionApi` methods backed
by `RuntimeKernelService` positive APIs. The old command operations,
`CommandOperation` variants, dispatch arms, command-response wrappers, command
source markers, and JS `operation`/`backend` command envelopes are retired for
these hot paths; `command_protocol.rs` proves the retired operation names are
unknown. Conformance now guards the typed APIs, direct Rust service methods,
retired command protocol entries, missing dispatch wrappers, source-scan
blockers, and absence of command-fallback source markers. This remained
non-terminal at that cut because coding-tool StepModule transport, deeper
durable replay/storage, MCP materialization, model_mount
backend/materialization work, and stable IDE/CLI/SDK protocol APIs still needed
terminal Rust daemon-core ownership. Slice 1228 retires the StepModule transport
blocker.

Slice 1227 retires the coding-tool result/artifact and diagnostics-repair
command transport family. Coding-tool result envelope planning, coding-tool
artifact draft planning, coding-tool artifact read projection, post-edit
diagnostics feedback planning, diagnostics-repair control, diagnostics-repair
retry-run planning, diagnostics-repair decision projection, and diagnostics
rollback repair policy projection now enter Rust through typed
`daemonCoreRuntimeControlApi` or `daemonCoreRuntimeProjectionApi` methods backed
by direct `RuntimeKernelService` APIs. `RuntimeContextPolicyCore` rejects the
old generic `daemonCoreInvoker` option, no longer builds command envelopes for
these hot paths, and sends no command `operation`/`backend` transport fields.
Rust command-protocol source-absence conformance now keeps the retired
coding/artifact/diagnostics operation names absent; at that historical cut Rust
still retained the temporary
`run_coding_tool_step_module` operation at that cut, and `command_dispatch.rs`
had no dispatch arms or response-wrapper error conversions for the retired
coding/artifact/diagnostics operations. The Rust bridge request/response
wrappers and command-source markers for this family were deleted, while
conformance guarded the typed APIs, direct Rust service methods, retired
operation catalog, missing dispatch wrappers, missing command response helpers,
and source-scan blockers. Slice 1228 retires the remaining StepModule command
transport.

Slice 1228 retires the coding-tool StepModule command transport. At that cut
the runtime daemon passed `daemonCoreWorkloadApi` through the temporary
Rust-workload runner facade, and the facade called `runCodingToolStepModule`
with canonical `ioi.runtime.coding-tool-step-module-request.v1` facts instead
of a daemon-core command envelope. Constructor backend/command/argv selectors
and generic `daemonCoreInvoker` failed closed, while retired backend/command env
selectors were absent from the facade. Slice 1262 supersedes that scaffolding by
deleting the facade and having the coding-tool invocation surface call the typed
workload API directly. Rust `coding_tool_step_module.rs` exposes the direct
`CodingToolStepModuleRunRequest` with deny-unknown deserialization, while
`RuntimeKernelService::run_coding_tool_step_module` owns the positive API.
`command_protocol.rs` now has an empty `DAEMON_CORE_OPERATIONS` catalog. At that
cut, `command_dispatch.rs` had no StepModule dispatch arm and the old
`ioi-step-module-bridge` binary was only a fail-closed artifact; Slices 1233 and
1234 delete those artifacts instead of preserving them as terminal scaffolding.
The coding-tool invocation surface consumes `workload_result` rather than a
bridge result, and conformance guards the typed API path plus absence of the old
command operation, command response wrapper, binary fallback, and JS
command-envelope request builder. This remains non-terminal because durable
replay/storage, MCP runtime materialization, model_mount backend/materialization
work, richer protocol APIs, and IDE/CLI/SDK clients still need terminal
Rust-owned projection/replay records; the StepModule command transport itself is
retired.

Slice 1229 retires the model_mount generic daemon-core invoker shim. The
mounted `ModelMountCore` now rejects constructor `daemonCoreInvoker` as a
retired compatibility option, stores only `daemonCoreModelMountApi`, deletes
`invokeDaemonCore()`, and no longer exports the daemon-core command schema
marker from `model-mount-core.mjs`. `ModelMountingState` no longer forwards the
daemon-wide invoker into model_mount, and route-decision default source now
reports `rust_model_mount_api` instead of a command-transport marker.
Conformance guards the retired option, absence of generic invoker storage,
absence of the direct-invoker fallback error, absence of the command schema
marker, and the no-bridge/no-command-env source scan. This remains non-terminal
because live external backend binary spawning/supervision, hosted/provider transport,
hosted provider auth materialization, invocation authority, remaining
non-OAuth cache scaffolding, durable replay/storage, richer MCP runtime
materialization, and stable IDE/CLI/SDK protocol APIs still need terminal
Rust-owned materialization and projection/replay records.

Slice 1230 retires the run-cancel command-shaped Rust owner wrappers. The
run-cancel policy child keeps only `RunCancelStateUpdateCore` and
`RunCancelAdmissionRequiredCore` plus the direct `RuntimeKernelService`
methods; `RunCancelCommandError`, `RunCancel*BridgeRequest`,
`plan_run_cancel_*_response`, and `rust_run_cancel_*_command` source markers
are deleted. `RuntimeContextPolicyCore` now normalizes run-cancel state updates
as `rust_run_cancel_state_update_api`, admission-required refusals use
`rust_run_cancel_admission_required_api`, and conformance fails if the old
command wrappers, bridge request types, or command source markers return. This
remains non-terminal because wallet/operator authority, cancellation
replay/projection storage, direct lifecycle protocol APIs, durable
replay/storage, and stable IDE/CLI/SDK protocol APIs still need terminal
Rust-owned records.

Slice 1231 retires the remaining runtime-control command-shaped Rust owner
wrapper cluster for coding-tool budget recovery and operator control. The
budget-recovery child now exposes only `CodingToolBudgetRecoveryStateUpdateCore`
and `CodingToolBudgetRecoveryControlCore`, while the operator-control child keeps
only `DiagnosticsOperatorOverrideStateUpdateCore`,
`OperatorTurnControlAdmissionRequiredCore`, `OperatorInterruptStateUpdateCore`,
and `OperatorSteerStateUpdateCore` plus the direct `RuntimeKernelService`
methods. `CodingToolBudgetRecoveryCommandError`,
`CodingToolBudgetRecovery*BridgeRequest`, `OperatorControlCommandError`,
`*Operator*BridgeRequest`, `plan_coding_tool_budget_recovery_*_response`,
`plan_diagnostics_operator_override_state_update_response`,
`plan_operator_*_response`, and the `rust_*_command` source markers are
deleted. `RuntimeContextPolicyCore` now normalizes these migrated
runtime-control responses as `_api` sources, and conformance fails if the old
command wrappers, bridge request types, command-source markers, or bridge-shaped
Rust owner tests return. This remains non-terminal because durable
runtime-control replay/projection, richer wallet/runtime-control authority,
deeper receipt/state-root binding, and stable IDE/CLI/SDK protocol APIs still
need terminal Rust-owned records.

Slice 1232 removes the remaining StepModule command-env selector surface from
the temporary JS Rust-workload runner. `createStepModuleRunnerFromEnv()` no
longer read `IOI_STEP_MODULE_BACKEND`, `IOI_STEP_MODULE_COMMAND`,
`IOI_STEP_MODULE_COMMAND_ARGS`, `IOI_RUNTIME_DAEMON_CORE_COMMAND`, or
`IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`; it read only workload transport handles
(`IOI_WORKLOAD_GRPC_ADDR` and `IOI_SHMEM_ID`) before constructing
`RustWorkloadStepModuleRunner`. Slice 1262 then deletes that runner facade and
moves the workload transport handles to the daemon composition boundary. Command
env compatibility is deleted rather than preserved as a runtime selector, and
conformance now requires the retired runner files to stay absent. This remains
non-terminal because durable replay/storage, MCP/model_mount materialization,
and stable IDE/CLI/SDK protocol APIs still need terminal Rust-owned
projection/replay records.

Slice 1233 deletes the retired `ioi-step-module-bridge` binary and tombstone
module. `crates/node/src/bin/ioi-step-module-bridge.rs` and
`crates/node/src/bin/ioi_step_module_bridge/mod.rs` are absent; the old bridge
can no longer return a fail-closed command-transport response, be selected as a
binary fallback, or preserve a root module where command wrappers could be
reintroduced. Conformance now requires the old `ioi-step-module-bridge` binary
and `ioi_step_module_bridge/mod.rs` tombstone are absent while still proving the
retired command operation, command response wrapper, binary fallback, and JS
command-envelope request builder cannot return. This remains non-terminal
because durable replay/storage, MCP/model_mount materialization, richer
Agentgres projection/replay records, and stable IDE/CLI/SDK protocol APIs still
need terminal Rust-owned records, but the StepModule bridge artifact itself is
gone.

Slice 1234 deletes the remaining Rust service-kernel command-dispatch transport
module. `crates/services/src/agentic/runtime/kernel/command_dispatch.rs` is
absent, `crates/services/src/agentic/runtime/kernel/mod.rs` no longer exports
`command_dispatch`, and the retired stdin/JSON helpers
`run_daemon_core_command_response_from_stdin`,
`run_daemon_core_command_from_stdin`,
`run_daemon_core_command_from_json_str`,
`run_daemon_core_command_from_value`, `CommandTransportError`, and
`dispatch_command_operation_response` cannot return. The empty
`command_protocol.rs` catalog remains only as a retired-operation guard for
source and conformance, not as an executable transport. This remains
non-terminal because durable replay/storage, MCP/model_mount materialization,
richer Agentgres projection/replay records, and stable IDE/CLI/SDK protocol APIs
still need terminal Rust-owned records, but the command-dispatch process
transport is gone.

Slice 1235 retires the daemon-wide generic `daemonCoreInvoker` pass-through.
`packages/runtime-daemon/src/service/runtime-daemon-service.mjs` now rejects a
top-level `daemonCoreInvoker` option before constructing the store,
`AgentgresRuntimeStateStore` also fails closed if the stale option is supplied
directly, and `createCodingToolApprovalPolicy()` constructs its default core
from typed `daemonCoreApprovalApi` instead of forwarding
`deps.daemonCoreInvoker`. Conformance now forbids the live daemon surfaces from
storing or forwarding `daemonCoreInvoker: options.daemonCoreInvoker`,
`this.daemonCoreInvoker = options.daemonCoreInvoker`, or
`daemonCoreInvoker: deps.daemonCoreInvoker` while preserving direct core-level
negative tests that retired compatibility options fail closed. This remains
non-terminal because remaining `rust_core_required` route edges still need
positive Rust materialization/projection APIs, but the daemon-wide generic
invoker handle can no longer be used as split-brain fallback scaffolding.

Slice 1236 binds MCP serve `tools/call` public result truth to Rust-authored
Agentgres live-result replay. Rust `runtime_mcp_serve.rs` now requires coding
tool receipt refs, emits materialized `ioi.runtime.mcp-live-result.v1` records
with protocol payload hashes, `runtime.mcp_serve` authorship, StepModuleRouter
ownership, and no retired JS/command/binary-bridge/compatibility fallback proof fields, and
`policy/mcp_memory.rs` replays `runtime.mcp_serve` live results while still
filtering JS-authored candidates. `runtime-mcp-serve-surface.mjs` now fails
closed without `commitRuntimeMcpLiveResultState`, runtime `stateDir`, or
`projectMcpLiveResultReplay`, commits the Rust live-result record, and returns
only the replayed protocol payload. This remains non-terminal because external
MCP transport execution, runtime containment sandboxing for live backends, and
stable SDK/IDE protocol APIs still need terminal Rust-owned records.

Slice 1237 hard-cuts hosted provider lifecycle/inventory metadata transport out
of the old refusal-marker compatibility lane. Rust provider lifecycle and
inventory planners now emit contained hosted metadata transport contracts with
`rust_materialized` execution status, cTEE no-plaintext custody checks,
wallet.network transport-authority evidence, and no retired JS/command/
binary-bridge/compatibility fallback proof fields. Public JS protocol adapters
must preserve and validate those Rust-authored contracts, and they now reject the
retired `hosted_provider_transport_not_executed` evidence marker before hosted
provider lifecycle or inventory truth can return. This remains non-terminal
because live external hosted API/model payload execution, richer hosted catalog
materialization, deeper receipt/state-root binding, and stable SDK/IDE provider
protocol APIs still need terminal Rust-owned records.

Slice 1238 hard-cuts model_mount MCP workflow execution out of the admitted-but-
pending result lane. Rust `plan_model_mount_mcp_workflow` now materializes
deterministic protocol result payloads for MCP tool invocation and workflow-node
execution, binds their `result_payload_hash` into the control details,
`ioi.model_mount.mcp_workflow_receipt.v1` receipt, and StepModuleRouter result,
and marks `model_mount_mcp_result_materialized: true` with
`rust_materialized` status. The JS model-mount core and mounted state path now
reject stale pending-materialization plans before public truth can return, and
receipt-write guards reject direct MCP execution receipt appends without the
Rust materialized result binding. Slice 1382 supersedes the MCP tool-invocation
transport blocker by requiring the Rust live backend executor before model_mount
tool truth can commit; live MCP discovery, broader runtime containment
sandboxing, and stable IDE/CLI/SDK protocol APIs still need terminal Rust-owned
records.

Slice 1382 hard-cuts model_mount MCP tool invocation through the Rust MCP live
backend executor. Rust `plan_model_mount_mcp_workflow` now requires canonical
`thread_id`, `agent_id`, and `workload_spec` for `model_mount.mcp_tool.invoke`,
emits an `ioi.runtime.mcp-backend-execution.v1` contract bound to
`ioi_drivers::mcp::McpManager` / `McpTransport`, and provides a planned
`ioi.runtime.mcp-live-result.v1` result object for the backend executor. The
mounted daemon model_mount path receives `contextPolicyCore` from daemon startup
and calls `executeRuntimeMcpLiveBackend()` before model_mount record-state commit
or MCP execution receipt-state commit. If the executor, backend contract,
workload spec, Rust-authored content receipt, live result payload, or Rust driver
hash is missing, no model_mount MCP tool truth commits. Successful tool
invocation binds `runtime_mcp_live_backend_rust_driver_executed`,
`runtime_mcp_live_backend_actual_mcp_manager_io`, and
`runtime_mcp_live_backend_no_js_transport` evidence into the public response,
record details, and receipt, stamps `transport_execution_status:
"rust_driver_executed"`, and carries the Rust driver-result hash into
`result_payload_hash`, the StepModule result binding, and receipt details. The
old plan-only deterministic MCP tool payload remains admissible planning data
only; it cannot be terminal public truth or a compatibility fallback.

Slice 1267 hard-deletes the model_mount MCP workflow fallback-proof protocol
shape. Rust `plan_model_mount_mcp_workflow` no longer serializes
`js_registry_mutation`, `js_receipt_gate_dispatch`,
`js_transport_invocation`, `js_route_test`, `js_model_invocation`,
`js_mcp_tool_invocation`, `js_result_synthesis`,
`command_transport_fallback`, `binary_bridge_fallback`,
`compatibility_fallback`, or `legacy_js_result_fallback` as false-valued proof
fields on MCP server, MCP tool, workflow-node, or materialized result payload
contracts.
The JS model-mount core treats those keys as retired compatibility fields and
fails closed if they reappear in the public response, record details, or
receipt/result payloads. Conformance now requires the MCP workflow Rust source
to stay free of those false-valued fallback fields and requires the JS negative
guard that rejects stale fallback-proof responses.

Slice 1268 hard-deletes the hosted provider lifecycle/inventory fallback-proof
protocol shape for migrated model_mount provider metadata transport contracts.
Rust `plan_model_mount_provider_lifecycle` and
`plan_model_mount_provider_inventory` no longer serialize
`js_transport_invocation`, `command_transport_fallback`,
`binary_bridge_fallback`, or `compatibility_fallback` as false-valued proof
fields on provider lifecycle, provider inventory, or nested transport-contract
records. The mounted JS provider boundary treats those keys as retired
compatibility fields and fails closed if they reappear in the normalized result,
Rust record, public response, or transport contract. Conformance now scans the
model_mount Rust/JS production source for the retired false-valued provider
transport fields and requires focused provider lifecycle/inventory negative
tests.

Slice 1269 hard-deletes the runtime MCP live/serve fallback-proof protocol shape
for migrated MCP live-result, backend-execution, receipt, and served-tool result
records. Rust `mcp_control_backend_execution_contract`,
`mcp_control_live_exit_receipt`, `mcp_control_live_exit_result`,
`project_runtime_mcp_serve_tool_result`, Agentgres MCP live-result fixtures, and
`RuntimeAgentService::execute_runtime_mcp_live_backend()` no longer serialize
`js_backend_execution`, `js_transport_invocation`,
`command_transport_fallback`, `binary_bridge_fallback`, or
`compatibility_fallback` as false-valued proof fields. Rust replay/backend
validation and the JS MCP control/serve protocol clients treat those keys as
retired compatibility fields and fail closed if they reappear in receipt
details, result details, backend-execution payloads, or served live-result
details. Conformance now scans the runtime MCP Rust/JS production source for
retired false-valued MCP fallback fields and requires focused MCP control/serve
negative tests.

Slice 1239 hard-cuts runtime MCP control live invoke/discovery exits out of the
admitted-but-pending transport-result lane. Rust
`plan_mcp_control_agent_state_update` now materializes deterministic
`ioi.runtime.mcp-live-result-payload.v1` protocol payloads for `mcp_invoke` and
`mcp_live_discovery`, hashes the payload, binds that hash through the live-exit
receipt, control record, `ioi.runtime.mcp-live-result.v1` Agentgres result
record, and replay projection, and stamps the result as `rust_materialized`.
Rust replay now rejects MCP control live-result records that still carry the
retired pending backend evidence, and the JS MCP control surface rejects
`admitted_pending_rust_transport` / `runtime_mcp_transport_backend_pending`
records before result-state commit or public truth can return. This remains
non-terminal because runtime containment sandboxing for live backends and stable
IDE/CLI/SDK protocol APIs still need terminal Rust-owned records.

Slice 1240 hard-cuts runtime MCP catalog live-discovery out of the deferred
projection lane. Rust `McpToolSearchProjectionCore` now marks live catalog
search summaries as `rust_mcp_live_discovery_materialized`, emits
`runtime_mcp_live_discovery_rust_materialized` evidence, keeps the retired
`rust_mcp_live_discovery_deferred` field false, and returns completed,
non-deferred catalog summaries for declared Rust-projected server rows. The JS
catalog surface and context-policy adapter preserve the Rust materialized field
as protocol output, while conformance rejects the old deferred-live-discovery
surface name and marker from the success path. This remains non-terminal because
runtime containment sandboxing for live backends and stable IDE/CLI/SDK protocol
APIs still need terminal Rust-owned records.

Slice 1241 hard-cuts runtime MCP control live results out of the generic
Rust-shaped backend-materialization lane. Rust `mcp_control_live_exit_result`
now requires every MCP-control live invoke/discovery result payload to carry an
`ioi.runtime.mcp-backend-execution.v1` `backend_execution` contract bound to
`ioi_drivers::mcp::McpManager` and
`ioi_drivers::mcp::transport::McpTransport`, with `tools/call` for invoke,
`tools/list` for discovery, custody/containment refs, Agentgres refs, and no
retired JS/command/binary-bridge/compatibility fallback proof fields. The
live-exit receipt and result details now carry
`runtime_mcp_backend_execution_rust_driver_bound` evidence and
`rust_driver_contract_bound` backend status, Rust replay filters MCP-control
live results that lack the driver-bound contract, and the JS MCP control surface
rejects missing backend contracts before receipt/result commit or public replay
can return. This remains non-terminal because the async daemon API still needs
to wire actual live MCP server process I/O through the Rust `McpManager`
backend under the recorded containment contract, then expose stable SDK/IDE/CLI
protocol APIs over those replay records.

Slice 1242 hard-cuts runtime MCP control live results out of the planner-direct
terminal-result lane. `RuntimeContextPolicyCore` now exposes the positive
`daemonCoreMcpApi.executeRuntimeMcpLiveBackend` request surface with
`ioi.runtime.mcp-live-backend-execution-request.v1`, and the MCP control
surface must call it before live-exit receipt/result state commits. The
committed live result must carry
`runtime_mcp_live_backend_rust_driver_executed` evidence plus
`rust_driver_executed` backend-execution observation details; if the backend
executor is absent or returns an unbound result, no receipt-state commit,
result-state commit, replay, or `writeAgent()` can run. Conformance now guards
the typed API, the backend execution -> receipt commit -> result commit ->
replay -> agent commit order, and the missing-executor failure. This remains
non-terminal because the new API
boundary still needs to be wired to actual live MCP server process I/O through
Rust `McpManager` under runtime containment, then exposed through stable
SDK/IDE/CLI protocol APIs over Rust replay records.

Slice 1243 wires that required MCP live-backend API to real Rust MCP process
I/O. `RuntimeAgentService::execute_runtime_mcp_live_backend()` now validates
`ioi.runtime.mcp-live-backend-execution-request.v1`, requires wallet authority,
cTEE custody, containment refs, and the Rust driver contract, and then calls the
mounted `ioi_drivers::mcp::McpManager` for `tools/call` or live
`tools/list`. `McpManager::list_admitted_tools_for_server()` performs a live
`McpTransport::list_tools()` query and filters the response to the server's
admitted receipt tools, while tool invocation continues through
`execute_tool_with_result()` and `WorkloadSpec` lease validation. The
underlying `McpTransport` now retains the spawned child process instead of
dropping a `kill_on_drop` child immediately after pipe extraction, so live stdio
JSON-RPC survives initialization. Rust tests execute both `tools/call` and
`tools/list` through the repo MCP stdio fixture, and conformance guards the
service API, admitted live discovery path, and child-retention fix. This remains
non-terminal because stable SDK/IDE/CLI protocol APIs over the Rust replay
records still need to close.

Slice 1244 closes the runtime MCP live-result receipt-order blocker. The public
MCP control surface now calls `executeRuntimeMcpLiveBackend()` before
`commitRuntimeReceiptState()` or `commitRuntimeMcpLiveResultState()` can run,
then commits only the Rust backend service's returned control/receipt/result
truth. `RuntimeAgentService::execute_runtime_mcp_live_backend()` now binds the
actual driver-result hash into the public result payload, recomputes the result
payload hash, updates the control and receipt hash bindings, and records
`runtime_mcp_live_backend_driver_result_hash` plus
`runtime_mcp_live_backend_rust_driver_executed` evidence before JS can persist
or replay live-result truth. Tests and conformance guard the
backend-execution-before-receipt/result-commit order, the old planner-direct
payload hash no longer remains terminal, and missing backend execution now fails
closed before any live-exit receipt-state or result-state commit. This remains
non-terminal because stable SDK/IDE/CLI protocol APIs over Rust replay records
still need to close.

Slice 1245 closes the broader runtime MCP serve admission blocker. Rust
`RuntimeMcpServeToolCallPlanCore` now requires wallet authority grant refs,
wallet authority receipt refs, cTEE custody refs, and transport containment
refs before it can plan a served `tools/call`; missing refs fail closed before
the coding-tool invocation surface can run. The Rust planner binds those refs
into the served StepModule invocation request and the Rust result projector
requires the same refs before emitting the `runtime.mcp_serve`
`ioi.runtime.mcp-live-result.v1` record. The JS MCP serve surface passes only
canonical snake_case admission refs to Rust, rejects incomplete Rust plans or
live results that omit the refs, commits only the Rust-authored live result,
and returns only replayed Rust protocol payloads. Tests and conformance guard
the authority/custody/containment refusal paths, retired fallback-proof field
rejection, and replay-before-return path. This remains non-terminal because stable
SDK/IDE/CLI protocol APIs over Rust replay records still need to close.

Slice 1246 closes the SDK/public-route MCP serve protocol gap. The public
daemon now implements the advertised
`/v1/threads/{thread_id}/mcp/serve` route before the generic thread dispatcher,
unwraps stable `ioi.runtime.mcp-serve-client.v1` protocol envelopes, and
forwards body-carried wallet authority grant/receipt refs, cTEE custody refs,
and transport containment refs into the Rust-owned MCP serve context. The SDK
clients at that cut required those admission refs, sent them in the protocol
body instead of query-string transport, and kept raw JSON-RPC as the message
being served. Tests and conformance guard the stable SDK body, the advertised
thread route, absence of admission refs in query strings, and Rust replay
context handoff. At that cut this remained
non-terminal because IDE/CLI protocol APIs and broader SDK route-family coverage
over Rust replay records still need to close.

Slice 1247 closes the IDE MCP serve client split. React Flow MCP serve state
nodes no longer carry an editable endpoint override or duplicate camelCase MCP
protocol body fields. The IDE builder now emits the canonical
`/v1/threads/{thread_id}/mcp/serve` daemon request with
`ioi.runtime.mcp-serve-client.v1`, body-carried allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, containment refs, and a raw JSON-RPC
`tools/list` message. Tests and conformance guard the endpoint override
retirement, canonical IDE body, and admission-ref fields. At that cut this
remained non-terminal because CLI protocol APIs and broader SDK route-family
coverage over Rust replay records still need to close.

Slice 1248 closes the CLI MCP serve client split. The Rust CLI TUI now treats
`/mcp serve` as a stable daemon protocol client for
`/v1/threads/{thread_id}/mcp/serve`, emits
`ioi.runtime.mcp-serve-client.v1` with allowed tools, wallet authority
grant/receipt refs, cTEE custody refs, containment refs, and a raw JSON-RPC
`tools/list` message, and rejects endpoint overrides, top-level
`/v1/mcp/serve`, query-string admission, and duplicate endpoint body fields.
Tests and conformance guard that the old CLI command transport cannot return.
At that cut this remained non-terminal because broader SDK route-family coverage
over Rust replay records still needed to close.

Slice 1249 retires the top-level MCP serve compatibility path. The public
daemon no longer handles `GET` or `POST /v1/mcp/serve`, the SDK no longer
exports the global `serveMcpRpc()` client or `RuntimeMcpServeRpcInput`, and MCP
serve JSON-RPC now enters through the canonical thread-scoped
`/v1/threads/{thread_id}/mcp/serve` protocol route. Tests and conformance guard
that `/v1/mcp/serve`, query-carried `thread_id` serve transport, the global SDK
client, and the global SDK request type cannot return. This remains
non-terminal because broader non-MCP SDK route-family coverage over Rust replay
records still needs to close.

Slice 1270 retires the rest of the runtime MCP top-level route/client family.
The public daemon no longer handles `/v1/mcp*`, the legacy model-mount daemon no
longer exposes `/api/v1/mcp*`, SDK global MCP catalog/control clients are gone,
and the standalone CLI live MCP aliases are deleted instead of being bridged
through compatibility transport. MCP status/search/fetch/serve projections now
advertise only `/v1/threads/{thread_id}/mcp*` daemon protocol routes, while the
thread-scoped MCP routes remain mounted surface clients over Rust-owned
admission, Agentgres replay, receipt/state-root binding, wallet authority, and
cTEE custody checks. Tests and conformance guard that the old route families,
SDK globals, CLI aliases, and projection route strings cannot return. This
remains non-terminal because broader non-MCP SDK route-family coverage over Rust
replay records still needs to close.

Slice 1271 retires the runtime doctor/readiness missing-core compatibility
fallback. `/v1/doctor` still calls the mounted doctor aggregate directly, but
the aggregate no longer catches `runtime_tool_catalog_rust_core_required` or
`runtime_skill_hook_registry_rust_core_required` to synthesize degraded tool,
runtime-node, or skill/hook readiness rows. Missing Rust projection APIs now
fail closed, and tests/conformance guard that the old degraded fallback message,
synthetic tool ids, empty runtime-node list fallback, and skill/hook fallback
catalog cannot return. This remains non-terminal because richer Rust-owned
diagnostic/readiness projections and stable IDE/CLI/SDK protocol APIs still need
to close.

Slice 1272 deletes the remaining runtime-service bridge-named profile helper.
The live daemon imports `runtime-profile.mjs` for runtime profile normalization;
`runtime-api-bridge.mjs` and `runtime-api-bridge.test.mjs` are gone; and
conformance guards both the deleted old path and the absence of
`RuntimeApiBridge` adapter exports. This prevents the retired runtime-service
command/binary bridge from persisting as a harmless-looking JS compatibility
module while runtime-service execution and replay move toward stable Rust
daemon-core protocol/API ownership.

Slice 1273 hard-cuts runtime doctor/readiness onto a positive Rust daemon-core
projection API. `/v1/doctor` now calls
`contextPolicyCore.projectRuntimeDoctorReport()` with only request context facts,
and Rust `runtime_doctor_report.rs` owns readiness checks, model_mount route/MCP
replay, runtime tool/runtime-node catalog projection, skill/hook catalog
projection, Agentgres state-dir/run/memory evidence, wallet.network redaction,
and provider-key redaction before public truth returns. The JS
`runtime-doctor-report.mjs` facade and test are deleted, daemon store no longer
constructs `runtimeDoctorReport`, and conformance rejects any return to
`store.runtimeDoctorReport`, the daemon-store `doctorReport()` wrapper,
doctor-specific mounted JS tool/skill surface composition, missing-core degraded
fallback strings, or the deleted facade files. This remains non-terminal because
broader stable IDE/CLI/SDK protocol APIs and remaining route-family coverage over
Rust replay records still need to close.

Slice 1274 hard-cuts Studio intent-frame routing onto a positive Rust
daemon-core projection API. `/v1/studio/intent-frame` now calls
`contextPolicyCore.projectStudioIntentFrame()` with only canonical request facts,
and Rust `studio_intent_frame.rs` owns artifact/retrieval/workspace/runtime-action
classification, effect-contract construction, required capability selection,
prompt hashing, and canonical `execution_mode` handling before public intent
truth returns. The JS `studio-intent-frame.mjs` classifier facade and test are
deleted, daemon startup no longer imports or injects `resolveStudioIntentFrame`,
and conformance rejects any return to the JS resolver, daemon-store route
wrapper, deleted facade files, or retired `executionMode` input alias passthrough.
This remains non-terminal because downstream wallet/cTEE admission, Agentgres
receipt/state-root binding for consequential intent execution, and broader
stable IDE/CLI/SDK protocol coverage still need to close.

Slice 1275 hard-cuts public computer-use provider/discovery projections onto a
positive Rust daemon-core API. `/v1/computer-use/providers` and
`/v1/computer-use/browser-discovery` now call
`contextPolicyCore.projectRuntimeComputerUse()` with only canonical request
facts, and Rust `runtime_computer_use.rs` owns provider-registry and
browser-discovery public truth before route responses return. The Rust projection
reuses the StepModule provider registry in `coding_tool_computer_use.rs`, shapes
host browser-process/CDP discovery in Rust, emits Rust receipt/evidence refs, and
ignores retired camelCase request aliases. The JS
`computer-use-provider-registry.mjs` and `browser-discovery.mjs` facades/tests
are deleted, daemon startup no longer imports or injects those route
dependencies, and conformance rejects any return to the JS facades or retired
route dependency names. This remains non-terminal because concrete provider
execution, direct Rust computer-use event materialization, cTEE custody, durable
Agentgres expected-head/state-root binding, replay/projection, and stable
IDE/CLI/SDK APIs still need to close.

Slice 1276 hard-cuts computer-use run materialization into Rust run-create
planning. The public run-create hot path no longer imports or calls the JS
`computer-use-projection.mjs` facade; `buildRun()` forwards only canonical
request facts in `computer_use_materialization_request`, and Rust
`RunCreateStateUpdateCore` consumes that request during
`plan_run_create_state_update`. Rust now rejects prebuilt JS `computerUse` or
`computer_use_projection` candidates, materializes `trace.computerUse`,
computer-use events, a `computer_use_trace` receipt, task-state evidence refs,
and the redacted `computer-use-trace.json` artifact before the run-create
projection is committed. The old JS facade/test are deleted, the remaining JS
event-contract module is non-authoritative protocol scaffolding, and
conformance rejects any return to JS-authored run materialization. This remains
non-terminal because concrete provider execution beyond run-create
materialization, direct provider/backend event admission, cTEE custody, durable
Agentgres expected-head/state-root binding across replay/projection, and stable
IDE/CLI/SDK APIs still need to close.

Slice 1277 retires the root `daemonCoreApi` compatibility mount for the
authority/governed-admission family. External capability authority, cTEE Private
Workspace, worker/service package admission, L1 settlement admission, and
governed-improvement proposal admission now accept only their explicit typed
daemon-core API handles (`daemonCoreAuthorityApi`, `daemonCoreCteeApi`,
`daemonCoreWorkerServiceApi`, or `daemonCoreGovernedAdmissionApi`). Supplying a
flat `daemonCoreApi` object, even one carrying the right method, fails closed as
a retired compatibility option before Rust invocation. Conformance now guards
that those five cores cannot recover the root compatibility mount, nested
`daemonCoreApi.*` fallback, command/env fallback, or generic invoker path. This
remains non-terminal because richer projection/replay records, deeper
Agentgres receipt/state-root binding, and stable IDE/CLI/SDK read APIs still
need terminal Rust-owned coverage.

Slice 1278 retires the remaining root `daemonCoreApi` compatibility mount for
the approval, Agentgres, workspace restore, and context-policy cluster.
Coding-tool approval, approval state, runtime Agentgres admission, workspace
restore/snapshot, and runtime context-policy now accept only their explicit typed
daemon-core API handles. Flat `daemonCoreApi` and nested `daemonCoreApi.*`
fallbacks fail closed before Rust invocation, even when they carry the matching
method. Conformance guards the retired root mount, the old nested selectors, the
generic invoker path, and command/env fallback for this cluster. This remains
non-terminal because durable replay/storage, richer wallet/cTEE authority,
deeper Agentgres receipt/state-root binding, and stable IDE/CLI/SDK read APIs
still need terminal Rust-owned coverage across the remaining hot paths.

Slice 1279 hard-cuts the mounted runtime bridge turn/control lifecycle facade.
Public runtime-service resume and turn submission no longer call
`agentRunLifecycleSurface.createRuntimeBridgeThreadControl` or
`agentRunLifecycleSurface.createRuntimeBridgeTurn`; the public thread-turn
surface now calls the direct Rust lifecycle adapter with typed
`daemonCoreThreadLifecycleApi` planning through `RuntimeContextPolicyCore`,
explicit run-builder/provider dependencies, Agentgres-backed `writeAgent` /
`writeRun` commits, and Rust thread/turn projection validation. The mounted
lifecycle surface no longer exposes those two facade methods, focused tests
prove the methods are absent, and conformance rejects any return to those
public-surface facade calls. This remains non-terminal because runtime-service
thread start still enters through the create-thread lifecycle surface, and
broader lifecycle completion still needs deletion/cancellation replay/projection,
durable wallet/cTEE authority, and stable IDE/CLI/SDK lifecycle APIs over
Rust-owned records.

Slice 1280 deletes the remaining mounted agent/run lifecycle facade from the
daemon hot path. Public agent/thread/run create routes, agent
archive/unarchive/resume/close/reload/delete routes, non-runtime thread
resume/turn creation, diagnostics repair retry-run creation, subagent
spawn/input/resume, and runtime-service thread creation now call direct
Rust-backed lifecycle functions with explicit planner, run-builder,
provider-gate, Agentgres commit, and projection dependencies. The daemon store
no longer constructs `agentRunLifecycleSurface`, `createRuntimeAgentRunLifecycleSurface`
is absent, focused tests prove the store property is absent, and conformance
rejects production source that restores that facade. This remains non-terminal
because durable lifecycle deletion/cancellation replay/projection, deeper
wallet/cTEE lifecycle authority, and stable IDE/CLI/SDK lifecycle protocol APIs
still need Rust-owned records across the remaining hot paths.

Slice 1281 hard-retires the public model route-control JS route-map truth path.
Public route upsert/test still require Rust `planModelMountRouteControl` and
Rust Agentgres model_mount record-state commit before returning, but they no
longer write Rust-planned records back into `state.routes` or pass JS
route-map `current_route` candidates to Rust. Mounted route selection now builds
its route/endpoints/providers candidate set from Rust read-projection list APIs
instead of `this.routes`, `state.endpoints`, or `state.providers` maps.
Focused route tests assert the JS route map remains untouched and public
write/test requests carry no JS current-route candidate, while conformance
rejects restored route-map writeback, route-map current-route reads, raw
mounted route lookup, and raw endpoint/provider map candidate transport in the
route-control builder. This remains non-terminal because hosted/provider
transport materialization, deeper wallet/cTEE route authority, Rust-owned
topology joins, and stable IDE/CLI/SDK route APIs still need to close.

Slice 1282 hard-retires provider lifecycle JS endpoint-map subject truth.
Public provider health/start/stop still require Rust
`planModelMountProviderLifecycle` and Rust Agentgres model_mount record-state
commit before lifecycle truth can return, but implicit endpoint/model subjects
are now selected from the Rust `endpoints` read-projection list instead of
`state.endpoints`. Focused provider tests seed a map-only endpoint and prove it
cannot produce a lifecycle request before Rust planning, while conformance
rejects restored `state.endpoints` enumeration in the provider lifecycle
request builder. This remains non-terminal because live hosted/provider
transport materialization, deeper receipt/state-root binding, Rust-owned
topology joins, and stable IDE/CLI/SDK provider lifecycle APIs still need to
close.

Slice 1283 hard-retires conversation-artifact control JS artifact-candidate
transport. Public create/action/export/promote still call Rust
`planRuntimeConversationArtifactControl` and Rust Agentgres artifact-state
commit before truth; action/export/promote now send runtime `state_dir`, Rust
`runtime_conversation_artifact_control.rs` replays admitted `artifacts/*.json`
records, rejects `artifact`/`artifacts` control candidates, and requires
`state_dir` for existing-artifact controls. The mounted JS surface no longer
calls `ConversationArtifactStore.list()` or sends artifact candidates for
control planning, and focused Rust/JS tests plus conformance guard that the
retired candidate path cannot return. This remains non-terminal because durable
ArtifactRef/PayloadRef admission, richer replay/storage, wallet/cTEE authority,
and stable SDK/IDE artifact APIs still need to close.

Slice 1284 hard-retires public subagent read JS subagent/run candidate
transport. Public subagent list/get/result still call Rust
`projectRuntimeSubagentProjection`; the mounted JS surface now sends runtime
`state_dir` instead of a `{subagents,runs}` projection bundle, Rust
`runtime_subagent_projection.rs` replays admitted `subagents/*.json` and
`runs/*.json` records, rejects the old projection candidate transport, and
requires `state_dir` for valid read projections. Focused Rust/JS tests and
conformance guard that the deleted `candidateSubagentProjectionFacts()` path and
candidate error cannot return. This remains non-terminal because subagent
control still coordinates current subagent/run mutation facts, and direct
StepModuleRouter delegation/execution, wallet authority, durable replay/storage,
and stable SDK/IDE subagent APIs still need to close.

Slice 1285 deletes the empty Rust daemon-core command-protocol substrate. The
kernel no longer exports `pub mod command_protocol`, and
`crates/services/src/agentic/runtime/kernel/command_protocol.rs` is absent
instead of preserving an empty `DAEMON_CORE_OPERATIONS` catalog or
`CommandEnvelope` validator as terminal scaffolding. Hypervisor conformance now
uses a virtual retired-marker surface only after proving the source file and
module export are absent, so old command operation strings, command-dispatch
arms, bridge binaries, command-env fallbacks, and command-envelope compatibility
paths cannot return as daemon hot-path authority. This command substrate is
terminally retired; the broader master guide remains non-terminal until durable
replay/storage, richer wallet/cTEE authority, model_mount/MCP materialization,
and stable IDE/CLI/SDK protocol APIs close over Rust-owned records.

Slice 1286 hard-cuts runtime bridge turn-submit projection-candidate
transport. `createRuntimeBridgeTurnRun()` no longer calls
`store.turnForRun(candidateRun)` before Rust planning and no longer sends a
JS-authored `projection` candidate into `planRuntimeBridgeTurnRunStateUpdate`;
the Rust `RuntimeBridgeTurnRunStateUpdateRequest` denies unknown fields and
focused Rust tests reject the retired `projection` field. The daemon now commits
only the Rust-planned `turn.runtime_bridge.submit` run through Agentgres-backed
`writeRun` before requesting the Rust-authored turn projection from the
committed run. Conformance guards absence of the pre-plan candidate projection,
the retired request field, and the old projection-mismatch compatibility path.
This removes a duplicate JS turn-projection truth handoff; broader lifecycle
completion remains non-terminal until run creation itself is Rust-authored from
canonical request facts, durable replay/storage, wallet/cTEE lifecycle
authority, and stable IDE/CLI/SDK lifecycle APIs close.

Slice 1287 hard-cuts runtime thread-event projection/replay cache transport.
`RuntimeThreadEventProjectionRequest` now requires runtime `state_dir`, denies
unknown fields, and derives latest sequence, current head, state root, and
existing idempotency keys by replaying admitted `events/*.jsonl` Agentgres
records in Rust before admitting any projected `thread.started` or run event.
`RuntimeThreadEventReplayRequest` also denies unknown fields and no longer
accepts caller-supplied `latest_seq`; replay derives the latest sequence from
the same admitted event log. The daemon projection path no longer reads
`store.runtimeEventStream()` or `store.latestRuntimeEventSeq()` to send
`latest_seq`, `expected_head`, or `existing_idempotency_keys`, and replay no
longer forwards a JS latest-seq candidate. Conformance guards the Rust state-dir
requirement, rejected retired projection cache fields, rejected replay
`latest_seq`, and the absence of the old JS cache-derived request fields. This
removes the duplicate event-head/idempotency truth handoff; broader thread-event
completion remains non-terminal until stable IDE/CLI/SDK event APIs consume Rust
projection/replay records without the temporary local hydration cache.

Slice 1288 hard-cuts runtime thread-event projection fact transport.
`RuntimeThreadEventProjectionRequest` no longer accepts `workspace_root`,
`agent`, or `runs`; Rust derives synthetic `thread.started` and run-event source
facts by reading admitted Agentgres `agents/*.json` and `runs/*.json` records
from `state_dir` before event admission. The daemon projection wrapper now sends
only `projection_kind`, canonical `thread_id`, `event_stream_id`, optional
`run_id`, and `state_dir`, and the thread-event replay surface routes
thread-start, whole-thread, and run projections through those protocol IDs
instead of forwarding JS agent/run objects. The retired
`runtimeThreadProjectionAgent`, `runtimeThreadProjectionRun`, and
`runtimeThreadProjectionRunEvent` helpers are deleted, Rust rejects the old fact
transport under `deny_unknown_fields`, and conformance guards the absent JS
helpers, absent `agent`/`runs`/`workspace_root` request fields, and the new
state-dir Agentgres source loader. This removes the duplicate JS agent/run fact
handoff for the runtime thread-event projector; the broader master guide remains
non-terminal until local replay-cache hydration, durable protocol read APIs, and
remaining IDE/CLI/SDK consumers move fully onto Rust-owned projection/replay
records.

Slice 1289 hard-cuts runtime thread-event admission cache transport.
`RuntimeThreadEventAdmissionRequest` now denies unknown fields, requires runtime
`state_dir`, and no longer accepts caller-supplied `latest_seq`,
`expected_head`, or `state_root_before`. Direct generic event append now sends
only the candidate event plus daemon state dir; Rust reads admitted
`events/*.jsonl` Agentgres records to derive latest sequence, current head, and
state root before admission, receipt/storage binding, projection watermarking,
and state-root-after calculation. The old JS path no longer calls
`store.latestRuntimeEventSeq()` or formats an expected head for this migrated
admission hot path, and conformance guards the fail-closed Rust request shape,
state-dir requirement, rejected cache fields, and scoped JS absence. This removes
the generic runtime-event head/state handoff as an authority input; the remaining
non-terminal work is to retire the temporary local replay-cache hydration and
move remaining SDK/IDE event reads fully onto Rust-owned protocol projection and
replay records.

Slice 1290 hard-cuts coding-tool event admission cache transport.
`CodingToolResultEventAdmissionRequest` and
`CodingToolCommandStreamAdmissionRequest` now deny unknown fields, require
runtime `state_dir`, and reject caller-supplied `latest_seq`, `expected_head`,
and `state_root_before`. The daemon result-event and command-stream admission
wrappers no longer call `store.latestRuntimeEventSeq()` or format expected heads;
they send only canonical event/request facts plus daemon state dir. Rust
`coding_tool_event.rs` reads admitted `events/*.jsonl` Agentgres records to
derive latest sequence, current head, and state root before result-event or
command-stream admission, storage binding, receipt binding, and projection
watermarking. Conformance guards both fail-closed request structs, state-dir
requirements, rejected cache fields, Rust state loaders, and scoped JS absence.
This removes the remaining coding-tool Agentgres admission head/state handoff as
a JS authority input; remaining coding-tool work is now durable read/projection
cleanup and stable API consumption rather than command/env, binary bridge, or
cache-head admission fallback.

Slice 1291 hard-cuts coding-tool duplicate-result replay out of the JS local
event cache. `CodingToolResultEventAdmissionCore` now checks admitted
`events/*.jsonl` Agentgres records for an existing result event with the same
idempotency key and returns a Rust `replayed` admission record with the
existing event, operation ref, storage admission evidence, state root, head,
receipt refs, payload refs, artifact refs, and projection watermark. The
coding-tool invocation surface no longer reads
`store.runtimeEventStream(...).idempotency` and is no longer wired to
`codingToolInvocationResultFromEvent` before workload execution/result-event
admission; duplicate handling is owned by Rust admission over admitted
Agentgres truth. Conformance guards the Rust replay path, the focused Rust
idempotency replay test, the focused JS no-cache-preflight test, and the
absence of the invocation-surface cache read or duplicate replay shaper. This
removes the last coding-tool result duplicate-truth shortcut before Rust
admission; remaining coding-tool work is durable read/projection cleanup and
stable API consumption rather than JS idempotency authority.

Slice 1292 hard-cuts pending diagnostics feedback off the JS local event
cache. `pendingDiagnosticsFeedbackForNextTurn()` now calls
`runtimeEventsForStream(..., { since_seq: 0 })`, which routes through the Rust
runtime thread-event replay API over admitted Agentgres `events/*.jsonl`
records, before selecting diagnostic completion events for feedback compaction.
It fails closed when the replay API is absent and no longer reads
`store.runtimeEventStream()` for pending diagnostics truth. Conformance guards
the Rust replay call, the focused no-local-cache test, and the absence of a
direct runtime event stream cache read in the diagnostics feedback surface.
This removes another diagnostics/runtime feedback duplicate truth path; broader
diagnostics completion remains non-terminal until wallet-governed repair
authority, durable diagnostics projection/replay storage, and stable SDK/IDE
diagnostics APIs close.

Slice 1293 hard-cuts workspace-trust acknowledgement replay and sequencing out
of the JS local event cache. `WorkspaceTrustControlStateUpdateCore` now accepts
runtime `state_dir`, replays admitted Agentgres `events/*.jsonl` records inside
Rust to resolve warning truth, and rejects restored `events` candidate transport
or caller-supplied `seq` transport. The JS workspace-trust state client sends
only the `state_dir` replay handle plus canonical request facts, no longer calls
`runtimeEventsForStream()` or `latestRuntimeEventSeq()`, and still admits only
the Rust-planned warning/acknowledgement event through Rust runtime-event
Agentgres admission. Conformance guards the Rust state-dir replay tests, the
retired `events`/`seq` transports, and the absence of local replay/sequence
cache reads in the workspace-trust state module. This removes another
workspace-trust split-brain replay boundary; deeper wallet/cTEE authority and
stable protocol APIs remain non-terminal.

Slice 1294 hard-cuts runtime-control state-event sequence cache transport out
of the JS facade cluster. The Rust policy core now shares
`latest_runtime_event_seq_from_state_dir()`, which reads admitted Agentgres
`events/*.jsonl` records under runtime `state_dir` and derives the latest
sequence for a thread or event stream before planning thread-control,
operator interrupt/steer, context-compaction, or MCP-control state updates.
Those Rust request structs now reject caller-supplied `seq`, and context
compaction rejects caller-supplied `previous_latest_seq`; missing `state_dir`
fails closed before planning. The JS thread-control, thread-turn
operator-control, context-policy, and MCP-control surfaces no longer call
`latestRuntimeEventSeq()` for these migrated paths and no longer send sequence
or previous-latest fields. Context-policy event admission also stops
preassigning the sequence and consumes only the Rust Agentgres admission result.
Conformance now guards the shared Rust replay helper, the retired request
fields, focused fail-if-called tests, and production-source absence of the JS
latest-sequence cache. Remaining work is durable runtime-control projection and
stable protocol API cleanup, not a JS sequence authority fallback.

Slice 1295 hard-cuts run-memory command resolution out of the JS memory cache
and fail-closed mutation placeholders. `resolveRunMemory()` now requires the
mounted thread-memory surface, calls Rust-owned public memory policy/path/list
projections before run construction, and uses the same Rust
`plan_runtime_memory_control` plus Agentgres `commitRuntimeMemoryState` path for
chat/API remember, edit, delete, enable, and disable commands. The old
`store.memory.pathProjection()`, `store.memory.effectivePolicy()`,
`store.memory.list()`, and run-memory mutation refusal path can no longer
author run memory truth; missing Rust projection/control fails closed before JS
cache reads. The daemon-store memory pass-through methods for remember, list,
policy, path, edit/delete, status/validation, and direct memory control-event
append are deleted, so migrated memory routes and run construction cannot
return through those compatibility handles. Remaining work is wallet/policy authority, cTEE private-memory
custody, durable memory replay/projection depth, and stable IDE/SDK memory APIs.

Slice 1296 hard-cuts runtime task/job runner injection scaffolding.
`createRuntimeTaskJobSurface()` no longer accepts `taskJobCreateRunner`,
`taskJobCancelRunner`, or `taskJobProjectionRunner`; task create, task/job
cancel, and task/job read projection moved onto the Rust daemon-core task/job
planners/projector before Agentgres-backed run persistence or route projection.
Daemon construction no longer wires parallel task/job runner handles, and
conformance guards that the retired alias names cannot return; Slice 1314
removes the remaining store-mounted planner/projector fallback. Remaining work
is durable task/job replay/projection depth, wallet/cTEE task authority, direct
lifecycle APIs, and stable IDE/CLI/SDK task/job clients, not a JS runner
fallback.

Slice 1297 hard-cuts diagnostics repair runner injection scaffolding.
`createRuntimeDiagnosticsRepairSurface()` no longer accepts
`diagnosticsRepairRunner`; diagnostics repair decision execution, direct
repair/override/retry event append, operator override state update, retry-run
planning, retry-result projection, decision projection, and repair policy
projection resolve only `store.contextPolicyCore` before entering the Rust
daemon-core diagnostics repair planners/projectors. Daemon construction no
longer wires a parallel diagnostics repair runner handle, focused tests mount
fake Rust planners/projectors only under `store.contextPolicyCore`, and
conformance guards that the retired alias name cannot return. Remaining work is
durable diagnostics repair replay/storage, wallet-governed repair authority,
cTEE custody where repair work touches private workspace state, and stable
IDE/CLI/SDK diagnostics clients, not a JS runner fallback.

Slice 1298 hard-cuts workflow-edit runner injection scaffolding.
`createRuntimeWorkflowEditSurface()` no longer accepts `workflowEditRunner`;
public workflow-edit proposal and apply controls resolve only
`store.contextPolicyCore` before Rust daemon-core workflow-edit control
planning and Rust runtime-event admission. Daemon construction no longer wires
a parallel workflow-edit runner handle, focused tests mount fake Rust planners
only under `store.contextPolicyCore`, and conformance guards that the retired
alias name cannot return. Remaining work is wallet approval authority depth,
workflow mutation custody, durable workflow-edit projection/replay,
ArtifactRef/PayloadRef binding where needed, and stable IDE/CLI/SDK
workflow-edit clients, not a JS runner fallback.

Slice 1299 hard-cuts run-cancel runner injection scaffolding. `cancelRun()` no
longer reads `state.runCancelRunner`; cancellation state planning and
admission-required refusal shaping now resolve through the Rust daemon-core
mount that the auxiliary surface passes explicitly before Agentgres-backed
`writeRun` persistence. Conformance guards that the retired runner alias cannot
return. Remaining work is wallet/operator authority depth, cancellation
replay/projection storage, and direct Rust lifecycle APIs, not a JS runner
fallback.

Slice 1300 hard-cuts coding-tool budget recovery runner injection scaffolding.
`createRuntimeCodingToolBudgetRecoverySurface()` no longer accepts
`codingToolBudgetRecoveryRunner`; retry completion, request-approval control,
and approve-override control resolve only `store.contextPolicyCore` before Rust
daemon-core budget recovery planning, wallet authority binding, and
Agentgres-backed `writeRun` persistence. Daemon construction no longer wires a
parallel budget recovery runner handle, focused tests mount fake Rust planners
only under `store.contextPolicyCore`, and conformance guards that the retired
alias name cannot return. Remaining work is durable recovery replay/projection
depth and stable IDE/CLI/SDK recovery clients, not a JS runner fallback.

Slice 1301 hard-cuts runtime tool catalog runner injection scaffolding.
`createRuntimeToolSurface()` no longer accepts `toolCatalogRunner`; account,
runtime-node, and tool catalog projections mount the positive
`contextPolicyCore` API directly before Rust daemon-core catalog projection.
Daemon construction no longer wires a parallel tool catalog runner handle,
focused tests mount fake Rust projectors only through `contextPolicyCore`, and
conformance guards that the retired alias name cannot return. Remaining work is
direct Rust catalog storage/replay depth, wallet/network authority on external
exposure, receipt/state-root binding, and stable protocol APIs, not a JS runner
fallback.

Slice 1302 hard-cuts skill/hook registry runner injection scaffolding.
`createRuntimeSkillHookSurface()` no longer accepts `skillHookRunner`; catalog,
skills, and hooks projections mount the positive `contextPolicyCore` API
directly before Rust daemon-core registry projection. Daemon construction no
longer wires a parallel skill/hook runner handle, focused tests mount fake Rust
projectors only through `contextPolicyCore`, and conformance guards that the
retired alias name cannot return. Remaining work is direct Rust governance and
catalog storage/replay depth, wallet authority where applicable,
receipt/state-root binding, and stable protocol APIs, not a JS runner fallback.

Slice 1303 hard-cuts repository workflow runner injection scaffolding.
`createRuntimeRepositorySurface()` no longer accepts `repositoryRunner`;
repository workflow projections mount the positive `contextPolicyCore` API
directly before Rust daemon-core repository projection. Daemon construction no
longer wires a parallel repository runner handle, focused tests mount fake Rust
projectors only through `contextPolicyCore`, and conformance guards that the
retired alias name cannot return. Remaining work is durable Agentgres-backed
repository workflow storage/replay, wallet authority for external exits,
receipt/state-root binding, and stable protocol APIs, not a JS runner fallback.

Slice 1304 hard-cuts runtime lifecycle projection runner injection scaffolding.
`createRuntimeLifecycleProjectionSurface()` no longer accepts
`lifecycleRunner`; public lifecycle projections mount the positive
`contextPolicyCore` API directly before Rust daemon-core Agentgres replay
projection. Daemon construction no longer wires a parallel lifecycle runner
handle, focused tests mount fake Rust projectors only through
`contextPolicyCore`, and conformance guards that the retired alias name cannot
return. Remaining work is wallet/cTEE authority on lifecycle exits,
receipt/state-root binding for every lifecycle read projection, richer
ArtifactRef/PayloadRef-aware artifact projection, and stable IDE/CLI/SDK
protocol APIs, not a JS runner fallback.

Slice 1305 hard-cuts the route-level lifecycle admission fallback. Public
agent/thread create routes and native agent status/delete/run-create routes no
longer accept a `lifecycleAdmissionRunner` handler option or fall back through
`store.contextPolicyCore ?? lifecycleAdmissionRunner`; those route families pass
only `store.contextPolicyCore` into the direct Rust-backed lifecycle functions.
Conformance now guards that the route fallback option and nullish fallback
shape cannot return. Remaining work is wallet/cTEE policy depth,
receipt/state-root binding, lifecycle replay/projection storage, and stable
protocol APIs, not an alternate JS route runner.

Slice 1306 hard-cuts thread-turn surface runner aliases.
`createRuntimeThreadTurnSurface()` no longer accepts `threadLifecycleRunner`,
`threadTurnAdmissionRunner`, or `operatorTurnControlAdmissionRunner`;
runtime-service resume/turn submit, public non-runtime resume/turn create, and
operator interrupt/steer planning all resolve through the single positive
`contextPolicyCore` mount. Conformance now guards that the retired aliases
cannot return. Remaining work is durable lifecycle replay/projection,
wallet/cTEE runtime-service authority, receipt/state-root binding, and stable
thread-turn protocol APIs, not alternate surface runners.

Slice 1307 hard-cuts runtime subagent runner wrappers.
`createRuntimeSubagentSurface()` no longer routes projection/control through
`subagentProjectionRunner`, `subagentControlRunner`, or
`store.contextPolicyCore ?? contextPolicyCore`; subagent list/get/result,
spawn, wait, input, resume, assign, cancel, propagated cancel, direct
control-event append, and child lifecycle composition resolve through the
single positive `contextPolicyCore` mount injected by daemon startup.
Conformance now guards that the retired wrappers and fallback cannot return.
Remaining work is direct Rust subagent admission/storage/replay,
StepModuleRouter delegation/execution authority, wallet/cTEE policy depth,
receipt/state-root binding, and stable SDK/IDE subagent protocol APIs, not
alternate subagent runners.

Slice 1308 hard-cuts diagnostics repair surface runner wrappers.
`createRuntimeDiagnosticsRepairSurface()` no longer routes diagnostics repair
decision control, retry-run planning, retry-result projection, decision
projection, or operator-override state update through
`diagnosticsRepairControlRunner`, `diagnosticsRepairRetryRunRunner`,
`diagnosticsRepairRetryResultProjectionRunner`, `diagnosticsRepairProjectionRunner`,
`diagnosticsOperatorOverrideStateUpdateRunner`, or
`store.contextPolicyCore ?? null`; decision execution, direct
decision/retry/operator event append, retry turn creation, retry-result
projection, decision projection, and operator override execution resolve
through the single positive `contextPolicyCore` mount injected by daemon
startup. Diagnostics retry lifecycle composition also passes that same core into
the direct Rust run-create path, so retry creation cannot recover by reading a
store-level fallback. Conformance now guards that the retired wrappers and
fallback cannot return. Remaining work is wallet-governed repair policy depth,
durable diagnostics repair projection/replay, receipt/state-root binding, cTEE
custody where repair work touches private workspace state, and stable SDK/IDE
diagnostics APIs, not alternate diagnostics repair runners.

Slice 1309 hard-cuts runtime agent/run lifecycle helper runner fallbacks.
`createAgent()`, `createThread()`, `createRun()`,
`createRuntimeBridgeTurnRun()`, and `createRuntimeBridgeThreadControl()` no
longer accept per-operation state-update runner deps or recover through
`store.contextPolicyCore ?? null`; agent create, thread create, run create,
runtime-service bridge thread start/control, and runtime-service turn submit
resolve through the explicit `lifecycleAdmissionRunner` dependency supplied by
the daemon route/surface caller. Conformance now guards that the retired
per-operation runner deps and store fallback cannot return. Remaining work is
wallet/cTEE lifecycle policy depth, durable lifecycle replay/projection,
receipt/state-root binding, and stable protocol APIs, not alternate lifecycle
helper runners.

Slice 1310 hard-cuts conversation-artifact surface runner wrappers.
`createRuntimeConversationArtifactSurface()` no longer routes artifact
create/action/export/promote control or list/get/revision projection through
`conversationArtifactControlRunner`, `conversationArtifactProjectionRunner`, or
the `store.contextPolicyCore ?? contextPolicyCore` fallback shape. Public and
thread-scoped conversation-artifact read/control routes now resolve through the
single positive `contextPolicyCore` mount injected by daemon startup before Rust
control planning, Rust projection, and Agentgres artifact-state commit.
Conformance now guards that the retired wrappers and fallback cannot return.
Remaining work is durable Agentgres-backed artifact replay/projection,
ArtifactRef/PayloadRef admission depth, wallet/cTEE authority where needed, and
stable protocol APIs, not alternate conversation-artifact runners.

Slice 1311 hard-cuts the runtime MCP serve store-core fallback. MCP serve
`tools/call` planning, Rust result projection, and live-result replay now
resolve only through the positive `contextPolicyCore` mount supplied to
`createRuntimeMcpServeSurface()` by daemon startup. The MCP serve surface and
focused tests no longer read or model `store.contextPolicyCore`, and the old
`store.contextPolicyCore ?? contextPolicyCore` fallback cannot return.
Conformance now guards the absence of that store-mounted planner path. Remaining
work is broader SDK route-family protocol coverage and deeper MCP replay/storage
cleanup, not an alternate MCP serve planner mount.

Slice 1312 hard-cuts the coding-tool artifact surface store-core fallback.
Artifact draft materialization and artifact read/retrieve projection now resolve
only through the positive `contextPolicyCore` mount supplied to
`createRuntimeCodingToolArtifactSurface()` by daemon startup. The artifact
surface no longer reads `store.contextPolicyCore ?? contextPolicyCore`, so draft
records, read projections, and result retrieval cannot return through a
store-mounted artifact planner/projector fallback. Conformance now guards that
the retired fallback cannot return. Remaining work is durable artifact
projection/replay depth, ArtifactRef/PayloadRef admission depth, and stable
protocol APIs, not an alternate artifact core mount.

Slice 1313 hard-cuts the coding-tool budget recovery surface store-core
fallback. Retry-approved state update, request-approval control, and
approve-override control now resolve only through the positive
`contextPolicyCore` mount supplied to
`createRuntimeCodingToolBudgetRecoverySurface()` by daemon startup. The budget
recovery surface and focused tests no longer read or model
`store.contextPolicyCore` or `store.contextPolicyCore ?? null`, so
budget-recovery run truth cannot return through a store-mounted planner
fallback. Conformance now guards that the retired fallback cannot return.
Remaining work is retry-event materialization, durable replay/projection, and
deeper approval authority projection, not an alternate budget recovery planner
mount.

Slice 1314 hard-cuts the runtime task/job surface store-core fallback. Task
create, task/job cancel, and task/job list/get projection now resolve only
through the positive `contextPolicyCore` mount supplied to
`createRuntimeTaskJobSurface()` by daemon startup. The task/job surface and
focused tests no longer read or model `store.contextPolicyCore` or
`store.contextPolicyCore ?? null`, so task/job run truth and read projection
cannot return through a store-mounted planner/projector fallback. Conformance
now guards that the retired fallback cannot return. Remaining work is durable
task/job replay/projection depth, wallet/cTEE task authority, direct lifecycle
APIs, and stable protocol clients, not an alternate task/job core mount.

Slice 1315 hard-cuts the runtime auxiliary compositor store-core fallback.
Managed-session projection/control, workspace-change projection/control, and
thread-fork control now resolve only through the positive `contextPolicyCore`
mount supplied to `createRuntimeThreadAuxiliarySurface()` by daemon startup.
The auxiliary surface passes that mount into the helper modules explicitly, and
the helper modules plus focused tests no longer read or model
`deps.contextPolicyCore ?? store.contextPolicyCore`, `store.contextPolicyCore`,
or `store?.contextPolicyCore`. Managed-session, workspace-change, and
thread-fork truth therefore cannot return through a store-mounted
planner/projector fallback after Rust daemon-core parity is present.
Conformance now guards the retired fallback and the daemon-mounted auxiliary
core dependency. Remaining work is durable replay/projection depth,
wallet/cTEE authority expansion, StepModuleRouter delegation execution, and
stable protocol clients, not an alternate auxiliary core mount.

Slice 1316 hard-cuts the runtime context-policy surface store-core fallback.
`compactThread()`, thread/run context-budget event planning, and
thread compaction-policy event planning now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeContextPolicySurface()` by
daemon startup. The surface and focused tests no longer read or model
`store?.contextPolicyCore ?? contextPolicyCore`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`, so context compaction, context-budget event truth,
and compaction-policy event truth cannot return through a store-mounted
planner/projector fallback. Conformance now guards the retired fallback, the
daemon-mounted context-policy surface, and the focused harness mount. Remaining
work is durable replay/projection depth, richer policy receipt/state-root
binding, wallet/cTEE authority expansion, and stable protocol clients, not an
alternate context-policy core mount.

Slice 1317 hard-cuts the runtime workflow-edit surface store-core fallback.
Workflow-edit proposal and apply controls now resolve only through the positive
`contextPolicyCore` mount supplied to `createRuntimeWorkflowEditSurface()` by
daemon startup. The workflow-edit surface and focused tests no longer read or
model `store?.contextPolicyCore ?? null`, `store.contextPolicyCore`, or
`store?.contextPolicyCore`, so workflow-edit proposal/apply event truth cannot
return through a store-mounted planner fallback after Rust daemon-core parity is
present. Conformance now guards the retired fallback, the daemon-mounted
workflow-edit surface, and the focused harness mount. Remaining work is durable
workflow-edit replay/projection depth, richer policy receipt/state-root
binding, wallet/cTEE workflow authority expansion, and stable protocol clients,
not an alternate workflow-edit core mount.

Slice 1318 hard-cuts the thread-memory/lifecycle store-core fallback cluster.
The thread-memory surface is now constructed per daemon instance with the
positive `contextPolicyCore` mount supplied by startup, so public memory
projection/control and memory status/validation event planning resolve only the
constructor-mounted Rust core. `updateAgent()` and `deleteAgent()` now default
their status/delete runners to `null` instead of `store.contextPolicyCore ??
null`; route and focused tests pass the Rust core explicitly. The source and
focused tests no longer model `store?.contextPolicyCore ?? contextPolicyCore`,
`store.contextPolicyCore ?? null`, or store-mounted lifecycle helper planner
fallbacks, and conformance guards the instance-owned memory surface plus null
lifecycle helper defaults. Remaining work is wallet/policy authority depth,
cTEE private-memory custody, durable memory/lifecycle replay and projection,
receipt/state-root binding, and stable IDE/CLI/SDK protocol clients, not an
alternate store-mounted Rust core fallback.

Slice 1319 hard-cuts the run-cancel state-core fallback. `cancelRun()` now
accepts the positive `contextPolicyCore` mount explicitly from
`createRuntimeThreadAuxiliarySurface()` and from subagent cancellation
composition; it no longer reads `state.contextPolicyCore` or
`state?.contextPolicyCore` for state planning or admission-required refusal
shaping. Focused cancellation tests mount fake Rust planners through the call
dependency object, subagent cancellation tests assert that the mounted core is
forwarded, and conformance guards the absent state lookup plus the auxiliary
surface call. Remaining work is wallet/operator authority depth, durable
cancellation replay/projection storage, direct Rust lifecycle APIs, and stable
protocol clients, not an alternate state-mounted Rust core fallback.

Slice 1320 hard-cuts the runtime MCP single-core mount fallback. Daemon startup
now injects the same positive `contextPolicyCore` mount into MCP catalog,
control, and serve surfaces; the catalog/control surfaces no longer instantiate
their own `RuntimeContextPolicyCore`, and `mcp-manager.mjs` requires an explicit
daemon-mounted core instead of self-creating one from `daemonCoreMcpApi`.
Registry, validation, catalog, status, search/fetch, live-result, and serve
truth therefore cannot return through a duplicate JS-side Rust-core instance
after daemon parity is present. Conformance now guards daemon injection, the
absence of MCP self-core defaults, and the manager's fail-closed explicit-core
requirement. Remaining work is broader non-MCP SDK route-family protocol
coverage and durable MCP replay/storage depth, not another MCP core fallback.

Slice 1321 hard-cuts the runtime context/memory auxiliary self-core and planner
alias fallbacks. Coding-tool invocation now passes the daemon-owned
`contextPolicyCore` into coding-tool budget policy preflight, and the
context-budget policy helpers no longer self-create `RuntimeContextPolicyCore`
for context-budget, coding-tool budget, or compaction-policy evaluation.
Workflow-only context-budget projection likewise requires the constructor-mounted
core instead of silently creating a duplicate helper core. The coding-tool
governance budget-block surface now accepts only the positive
`contextPolicyCore` mount and ignores the retired `codingToolBudgetBlockPlanner`
constructor alias, so budget-block truth cannot return through an alternate
planner. Thread-control construction defaults its core to `null` rather than a
self-created policy core, and memory-manager status/validation helpers require
an explicit daemon-mounted core instead of constructing one locally. Focused
tests and conformance guard the retired self-core defaults, the retired planner
alias, and the daemon injection path. Remaining work is durable policy/memory
replay and wallet/cTEE authority depth, not another helper-owned core fallback.

Slice 1322 hard-cuts the runtime-service thread-turn bridge-adapter constructor
aliases. `runtime-thread-turn-surface.mjs` no longer accepts
`runtimeBridgeThreadControl` or `runtimeBridgeTurnRun` overrides; runtime-service
resume and turn submission call the imported direct Rust lifecycle adapters
(`createRuntimeBridgeThreadControl()` and `createRuntimeBridgeTurnRun()`) with
the daemon-mounted `contextPolicyCore`. Focused tests mount fake Rust lifecycle
cores through `contextPolicyCore` and install throw-if-called retired aliases to
prove the old injected bridge handles cannot author runtime-service thread or
turn truth. Conformance guards the direct adapter calls and the absent
constructor aliases. Remaining work is durable lifecycle replay/projection,
wallet/cTEE runtime-service authority, and stable IDE/CLI/SDK lifecycle APIs,
not another bridge-adapter injection path.

Slice 1323 deletes the model_mount read-projection JS facade boundary.
`ModelMountingState` now calls the mounted `modelMountCore.planReadProjection()`
directly through `modelMountReadProjection()` for public model_mount readbacks,
canonical projection persistence, runtime-engine/catalog/server/backend/MCP/
conversation/topology projection reads, and not-found translations. The
standalone helper module is absent, the focused proof moved to
`read-projection-direct.test.mjs` and calls mounted state methods directly, and
route-family tests mount fake Rust cores only through `modelMountCore`.
Conformance guards the absent helper file/property plus direct
`modelMountReadProjection()` calls. Remaining work is direct Rust Agentgres
topology joins, hosted/provider materialization, backend execution
materialization, and stable SDK/IDE protocol APIs, not a JS read-projection
facade.

Slice 1324 hard-cuts the runtime thread-control existing-model compatibility
fallback. `threadRuntimeControlModelInput()` no longer accepts persisted
camelCase `existingModel` aliases (`routeId`, `reasoningEffort`, `maxCostUsd`,
`workflowGraphId`, or `workflowNodeId`) as model-route truth when building
canonical model-control input for Rust route selection. Focused tests keep the
canonical `route_id` / `workflow_node_id` path live while poisoning the retired
aliases to prove they cannot override the Rust-bound request, and conformance
guards the absence of the `existingModel.*` fallback reads. Remaining work is
wallet/model-route authority depth, durable replay/projection binding, and
stable IDE/CLI/SDK lifecycle APIs, not a thread-control compatibility fallback.

Slice 1325 hard-cuts the thread runtime-control top-level alias truth path.
`initialThreadRuntimeControls()`, `normalizedAgentRuntimeControls()`,
`RuntimeThreadControlSurface.nextThreadRuntimeControls()`, and the lifecycle
fallback seed now emit only canonical `approval_mode` runtime-control truth,
drop top-level `approvalMode` and `updatedAt`, and read persisted control
approval only from `approval_mode`. Runtime-backed turn requests produced by
`requestWithThreadRuntimeControls()` now scrub poisoned `threadMode` /
`approvalMode` request aliases and forward canonical `thread_mode` /
`approval_mode` into the direct Rust lifecycle path. Coding-tool approval and
repository/workspace-trust consumers read `controls.approval_mode`, focused
tests poison the retired aliases while proving they cannot return as output, and
conformance guards the helper, surface, and lifecycle fallback against restoring
the alias fields. Remaining work is wallet/model-route authority depth, durable
replay/projection binding, and stable IDE/CLI/SDK lifecycle APIs, not a
thread-control top-level alias truth path.

Slice 1326 hard-cuts the model_mount backend-process JS cache substrate.
`ModelMountingState` no longer constructs `backendProcesses` or
`backendChildProcesses`, no longer exposes `listBackendProcesses()`,
`backendProcessForBackend()`, or `reconciledBackendProcess()`, the
`backend-processes` persistence map and store directory are gone, and
`backend-registry-state.mjs` no longer exports backend-process list/lookup/
reconcile helpers. Rust aggregate `snapshot` and `projection` outputs also no
longer emit the empty `backendProcesses` compatibility slot. Backend-process
and backend-lifecycle planning remain typed Rust daemon-core APIs, backend list
and log readbacks remain Rust read-projection/replay records, and JS process
supervisor entrypoints remain fail-closed before any subprocess authority.
Conformance now guards the absent daemon fields, helper exports, persistence
map, store directory, Rust aggregate compatibility field, and focused absence
assertions. Remaining work is actual Rust live external backend binary spawning/supervision,
hosted/provider transport, the invocation-authority blocker later superseded by Slice 1381, and stable SDK/IDE/CLI
protocol APIs, not a JS backend-process cache fallback.

Slice 1327 hard-cuts the model_mount OAuth session/state JS cache substrate.
`ModelMountingState` no longer constructs `oauthSessions` or `oauthStates`, the
`oauth-sessions` and `oauth-states` persistence map entries and store
directories are gone, and focused OAuth/read-projection tests now assert those
local map fields are absent instead of merely empty. Public
`listOAuthSessions()`, `listOAuthStates()`, `snapshot()`, and `projection()`
continue to return OAuth records through Rust Agentgres read-projection replay;
the Rust aggregate keeps the protocol fields as Rust-authored output, not JS
state. Conformance guards the absent daemon fields, persistence map entries,
store directories, and focused absence assertions while preserving Rust replay
coverage for OAuth session/state records. Remaining work is hosted OAuth/
live cTEE secret injection into outbound hosted network requests, actual Rust live external backend binary spawning/supervision,
hosted/provider transport, the invocation-authority blocker later superseded by Slice 1381, and stable SDK/IDE/CLI
protocol APIs, not a JS OAuth session/state cache fallback.

Slice 1328 hard-cuts the model_mount legacy capability-token JS cache
substrate. `ModelMountingState` no longer constructs a `tokens` map, the
legacy `tokens` persistence entry and store directory are gone, and focused
capability-token/state/store tests assert the JS cache field and directory are
absent rather than merely untouched. Public capability-token
create/list/authorize/revoke still enter Rust daemon-core
`plan_model_mount_capability_token_control`, commit `capability-tokens` records
through Agentgres, and return or replay Rust-owned token authority facts; the
one-time token material remains outside persisted records. Conformance guards
the absent daemon field, persistence map entry, store directory, and focused
absence assertion. Remaining work is deeper wallet authority policy, revocation
epochs, and stable SDK/IDE/CLI capability-token APIs, not a JS `tokens` cache
fallback.

Slice 1329 hard-cuts the model_mount catalog-provider configuration/runtime
material JS cache substrate. `ModelMountingState` no longer constructs
`catalogProviderConfigs` or `catalogProviderRuntimeMaterials`, the legacy
`model-catalog-providers` persistence entry and store directory are gone, and
focused catalog-provider/state/store tests assert those local fields and the
directory are absent instead of seeded and untouched. Public catalog-provider
config list/get/write, private config readback, runtime-material resolution,
and OAuth start/callback/exchange/refresh/revoke still enter Rust
`plan_model_mount_catalog_provider_control` and commit
`model-catalog-provider-controls` records through Agentgres before public
truth returns. Conformance guards the absent daemon fields, persistence map
entry, store directory, and focused absence assertions. Remaining work is
live cTEE secret injection into outbound hosted network requests, richer hosted catalog transport/materialization,
and stable SDK/IDE/CLI catalog-provider APIs, not a JS catalog-provider config
or runtime-material cache fallback.

Slice 1330 hard-cuts the model_mount invocation helper compatibility-alias
path. Migrated model invocation, provider execution, and provider-result helper
boundaries now reject retired camelCase selection, route receipt/control,
endpoint/provider, instance/backend-process, token, provider-result, stream,
MCP, and evidence helper fields before shaping provider execution admission or
provider-result admission requests. The helper normalizers read only canonical
snake_case Rust model_mount records, so stale `routeReceipt`, `routeDecision`,
`executionBackend`, `tokenCount`, `streamChunks`, or similar compatibility
fields cannot become route, provider execution, token, stream, or provider
result truth. Focused tests and conformance poison those aliases while keeping
canonical snake_case records live. Remaining work is backend
execution/materialization, hosted/provider transport, invocation authority
depth, and stable SDK/IDE/CLI protocol APIs, not helper-level compatibility
translation on the migrated model_mount invocation hot path.

Slice 1250 retires the top-level runtime memory context route family. The
public daemon no longer handles `/v1/memory`, `/v1/memory/records`,
`/v1/memory/policy`, `/v1/memory/path`, or `/v1/memory/validate`; the daemon
store no longer exports `memoryProjectionForContext`, `memoryStatus`, or
`validateMemory`; and the SDK no longer exports global `getMemoryStatus()` /
`validateMemory()` clients or their context-query input types. Runtime memory
status/validation now enters through explicit
`/v1/threads/{thread_id}/memory/status` and
`/v1/threads/{thread_id}/memory/validate` protocol routes, while memory
list/policy/path remain explicit thread/agent protocol routes over the
Rust-owned projection records. Tests and conformance guard that the retired
top-level memory routes, SDK globals, and daemon-store context helpers cannot
return. This remains non-terminal because wallet/policy authority, cTEE
private-memory custody, richer durable memory replay/projection, and stable IDE
memory APIs still need to close.

Slice 1251 hard-retires the RuntimeAgentService command/binary bridge
substrate and Slice 1272 deletes the bridge-named JS profile helper module.
`runtime-api-bridge.mjs` is absent, runtime profile normalization lives in
`runtime-profile.mjs`, the `ioi-runtime-bridge` binary and Cargo bin entry are deleted, daemon startup
rejects `runtimeBridge`, Rust service policy no longer reads bridge command-env
overrides, Autopilot uses the renamed inference/model-route helper instead of a
bridge helper, and stale bridge-backed live proof scripts/tests are removed.
Conformance now guards that the JS adapter export, bridge helper, bridge env
fallback, deleted bridge module path, Cargo bridge binary, and service
`runtimeBridge` option cannot return.
This bridge family is terminally retired; the broader master guide remains
non-terminal until runtime-service execution and replay land through stable Rust
daemon-core protocol APIs with Agentgres truth.

Slice 1252 retires the thread/run/subagent lifecycle command-shaped Rust owner
wrapper cluster. Thread control, runtime bridge thread start/control/turn,
subagent record updates, and agent/thread/run create/status/delete now expose
only direct Rust daemon-core request/record APIs in
`policy/thread_lifecycle.rs`; `ThreadLifecycleCommandError`, lifecycle
`*BridgeRequest` structs, `plan_*_state_update_response` wrappers,
`rust_*_state_update_command` source markers, policy facade exports, and
bridge-shaped owner tests are deleted. `RuntimeContextPolicyCore` now names
these as typed API result normalizers with `rust_*_state_update_api` defaults,
and conformance guards that no migrated lifecycle hot path can re-enter through
the retired command-shaped wrapper layer. This bridge-wrapper family is
terminally retired; broader lifecycle completion still depends on moving the
remaining local cache/replay and stable IDE/CLI/SDK lifecycle read APIs fully
onto Rust-owned Agentgres projection/replay records.

Slice 1253 hard-cuts runtime thread-event replay off JS replay candidates. Rust
`RuntimeThreadEventReplayRequest` now requires runtime `state_dir`, replays
admitted `events/*.jsonl` Agentgres event records in Rust, and rejects
caller-supplied replay `events` transport. The daemon passes only replay kind,
cursor, latest seq, and `state_dir` into
`project_runtime_thread_event_replay`; the old JS
`runtimeThreadReplayCandidateEvents` collector is deleted. Public run lifecycle
replay now reaches the mounted Rust thread-event replay path through
`eventsForRun`, and the duplicate `replayFromCanonicalState` daemon/run-read
facade is retired. Conformance guards the state-dir replay requirement, the
retired event-candidate transport, and absence of the public replay alias. This
removes a split-brain replay boundary for stream/turn/run replay; broader
lifecycle completion still depends on moving the remaining lifecycle projection
candidate facts and stable IDE/CLI/SDK read APIs fully onto Rust-owned
Agentgres projection records.

Slice 1254 hard-cuts public lifecycle projection off JS cache candidates. Rust
`RuntimeLifecycleProjectionRequest` now requires runtime `state_dir`,
replays admitted `agents/*.json`, `runs/*.json`, and `events/*.jsonl`
Agentgres records in Rust, and derives public agent/thread/run/turn/event,
run replay, usage, trace, computer-use, scorecard, and artifact projections
from those records. Rust rejects retired lifecycle candidate transport fields
such as `agents`, `runs`, `events`, `replay`, `usage`, `trace`, `artifacts`,
and `artifact`; the daemon lifecycle surface now sends only route identifiers
plus `state_dir` and no longer calls JS agent/run maps, thread/turn helpers,
usage helpers, event/replay streams, trace helpers, or artifact resolvers before
the Rust projection. Conformance guards the `state_dir` requirement, retired
candidate transport, daemon no-cache-call surface, and the updated run replay
alias retirement. This removes the public lifecycle read split-brain projection
boundary; broader lifecycle completion still depends on wallet/cTEE authority
for lifecycle exits, complete receipt/state-root binding for every lifecycle
read projection, and stable IDE/CLI/SDK protocol APIs over the Rust-owned
Agentgres replay records.

Slice 1255 folds the remaining top-level usage and authority-evidence public
read family into the Rust lifecycle projector. Rust
`project_runtime_lifecycle` now exposes `usage_list` and
`authority_evidence_summary` projection kinds over runtime `state_dir`, derives
usage rows and authority/preflight evidence from admitted Agentgres
`runs/*.json` and `events/*.jsonl` records, and keeps the projection source
bound to `rust_runtime_lifecycle_state_dir_replay`. Public `/v1/usage`,
`/v1/authority-evidence`, and `/v1/workflow-capability-preflights` call the
mounted lifecycle projection surface; the run-read surface no longer exposes
`listUsage` or `authorityEvidenceSummary`, and the old JS
`authority-evidence-summary.mjs` helper/test are deleted. Conformance now
guards the Rust projection kinds, lifecycle route calls, absent helper files,
and absent run-read usage/evidence facade. This removes the last public
lifecycle read exception that still returned through JS run-read authority;
broader lifecycle completion still depends on wallet/cTEE authority for
lifecycle exits, complete receipt/state-root binding for every lifecycle read
projection, and stable IDE/CLI/SDK protocol APIs over the Rust-owned Agentgres
replay records.

Slice 1256 retires the authority-evidence native compatibility aliases after
Slice 1255 verified Rust lifecycle projection parity. The daemon no longer
routes `/api/v1/authority-evidence`, `/api/v1/authority-evidence-summaries`,
`/api/v1/workflow-capability-preflight-evidence`, or
`/api/v1/workflow-capability-preflight`; the canonical protocol clients must
use `/v1/authority-evidence` or `/v1/workflow-capability-preflights`.
Conformance now guards the absence of those native aliases so the migrated read
family cannot regain a duplicate compatibility truth path.

Slice 1257 hard-cuts the diagnostics repair retry result facade. Rust
`RuntimeDiagnosticsRepairRetryResultProjectionCore` now owns the retry result
projection through typed
`daemonCoreRuntimeProjectionApi.projectRuntimeDiagnosticsRepairRetryResult`;
the daemon requires that projection API before JS agent lookup/run creation,
admits the Rust-authored retry event, validates the complete Rust-projected
result after admission, rejects partial or mismatched projections, and returns
only the Rust-projected retry result envelope without locally filling missing
fields. The old JS `diagnosticsRepairRetryResultFromEvent`,
`diagnosticsOperatorOverrideResultFromEvent`,
`diagnosticsRepairApplyApprovalKey`, and `diagnosticsRepairExecutionStatus`
helpers plus the stale daemon constructor wiring are deleted.
Command-protocol source absence keeps
`project_runtime_diagnostics_repair_retry_result` out of command transport, and
conformance now guards the positive typed API, the retired helper exports, the
fail-closed missing/partial projection paths, and the absence of JS
retry/operator result helper wiring. This removes the diagnostics repair retry
result split-brain projection fallback; broader diagnostics completion still
depends on durable
diagnostics repair storage/replay, wallet-governed repair policy authority, and
stable IDE/CLI/SDK diagnostics APIs over Rust-owned records.

Slice 1258 hard-cuts the IDE diagnostics repair client compatibility body. The
React Flow diagnostics repair node now emits only the canonical daemon protocol
body for `/v1/threads/{thread_id}/diagnostics/repair-decisions/{decision_id}/execute`:
snake_case schema, workflow, event, approval, conflict, and idempotency facts
plus the diagnostics repair decision action. The daemon diagnostics repair
surface rejects retired camelCase request aliases such as `decisionId`,
`snapshotId`, `workflowGraphId`, `workflowNodeId`, `approvalGranted`,
`allowConflicts`, `restoreApplyIdempotencyKey`, and `payloadSchemaVersion`
before Rust planning or runtime-event admission, and forwards the canonical
protocol body into Rust diagnostics repair control planning. Conformance now
guards both the daemon alias rejection and the IDE canonical request body. This
removes the diagnostics repair IDE compatibility body as a duplicate client
truth path; broader diagnostics completion still depends on durable diagnostics
repair storage/replay, wallet-governed repair policy authority, and any
remaining CLI/SDK diagnostics read APIs over Rust-owned records.

Slice 1259 hard-cuts runtime-service lifecycle agent projection aliases. Rust
thread-lifecycle start/control planning now scrubs caller-supplied
`runtimeProfile`, `runtimeSessionId`, `runtimeBridgeId`,
`runtimeBridgeStatus`, `runtimeBridgeSource`, and `fixtureProfile` before
returning Agentgres-bound agent projections, emits only canonical snake_case
runtime-service identity/custody fields, and lifecycle/thread-event/workspace
trust Rust replay/projection readers no longer accept those camel aliases as
truth. The JS runtime-service lifecycle normalizers fail closed if Rust returns
any retired alias, and daemon runtime identity/session helpers read only
`runtime_profile`, `runtime_session_id`, and `fixture_profile`. Conformance now
guards Rust alias scrubbing, JS normalizer rejection, and snake-only helper
reads. This removes another runtime-service compatibility truth path; broader
lifecycle completion still depends on durable wallet/cTEE authority,
deletion/cancellation replay/projection, and stable IDE/CLI/SDK lifecycle APIs
over Rust-owned records.

Slice 1260 hard-cuts diagnostics-blocked non-runtime turn creation out of the
admission-required refusal path. When post-edit diagnostics feedback blocks
continuation, the thread-turn surface now injects the Rust-projected
diagnostics feedback into the canonical turn request, enters the mounted Rust
run-create lifecycle path, commits only the Rust-planned blocked run through
Agentgres-backed `writeRun`, and returns the Rust thread/turn projection for
that run. The retired `thread_turn_diagnostics_block` /
`turn.diagnostics_block` operation is no longer accepted by
`ThreadTurnAdmissionRequiredCore`, and conformance now guards that
diagnostics-blocked turns cannot re-enter that refusal path or direct JS
`createRun()` / `updateAgent()` mutation. This removes a fail-closed-only
lifecycle route edge; deletion/cancellation replay/projection, direct
runtime-control event materialization, durable diagnostics replay/storage,
wallet/cTEE authority, broader run lifecycle, and stable protocol APIs remain
non-terminal.

Slice 1261 hard-cuts public approval request issuance into Rust authority.
`RuntimeApprovalStateCore` now exposes the typed
`authorizeApprovalRequest` approval API, backed by Rust
`ApprovalRequestAuthorityCore::authorize`. The public approval request surface
must call that Rust authority method before `planApprovalRequestStateUpdate`,
and the Rust request state planner now rejects missing request-authority
record/hash/authority-receipt binding. The JS surface forwards the Rust
request-authority receipts/hash into state planning and cannot fall back to
caller receipt truth, JS runtime-event append, JS run/agent target lookup,
command/env fallback, generic command transport, or bridge command wrappers.
Conformance guards the positive API, the failure path without request
authority, command-transport retirement for `authorize_approval_request`, and
the two-step public request ordering. Approval grant issuance, richer authority
projection/replay storage, durable approval read APIs, wallet/cTEE authority
coverage across the remaining routes, and stable IDE/CLI/SDK protocol APIs
remain non-terminal.

Slice 1265 hard-cuts approval decision authority onto typed wallet.network
approval-grant artifacts. `ApprovalDecisionAuthorityRequest` now accepts
`wallet_approval_grant`, Rust `ApprovalDecisionAuthorityCore` verifies the grant
structure for approve, reject, and revoke decisions, derives the canonical grant
artifact hash/ref, records `wallet_approval_grant_hash` and
`wallet_approval_grant_ref`, and uses that derived ref as the approval wallet
authority. The public JS approval surface forwards the typed grant object but
always blanks caller `authority_grant_refs`, so approval decisions can no longer
return through JS-minted `wallet.network://grant/...` strings. Conformance guards
the typed field, the approve/reject/revoke missing-grant negative paths, the
facade blanking behavior, the revoke forged-ref regression case, and the Rust
authority-derived state-update grant refs. Broader wallet.network grant issuance
and signature/consumption semantics, richer durable authority projection/replay
storage, and stable IDE/CLI/SDK approval APIs remain non-terminal.

Slice 1262 deletes the temporary StepModule runner facade from the daemon hot
path. `packages/runtime-daemon/src/step-module-runner.mjs` and its focused test
are absent, `AgentgresRuntimeStateStore` no longer imports or constructs
`createStepModuleRunnerFromEnv()`, and the coding-tool invocation surface calls
`daemonCoreWorkloadApi.runCodingToolStepModule` directly after Rust result
envelope planning returns the StepModule context. The direct request carries the
canonical `ioi.runtime.coding-tool-step-module-request.v1` facts and keeps
command `operation`, command `backend`, JS-supplied `invocation`, command-env
selectors, binary bridge fallback, and generic daemon-core invoker semantics out
of the migrated coding-tool execution path. Workload transport handles remain
daemon composition inputs only (`IOI_WORKLOAD_GRPC_ADDR` and `IOI_SHMEM_ID`);
they do not reintroduce command transport or JS execution authority.
Conformance now guards the deleted runner files, direct typed workload API
usage, missing-API fail-closed behavior, and absence of the retired command/env
selectors. Durable diagnostics replay/storage, remaining model_mount/MCP
materialization, richer authority projection/replay, and stable IDE/CLI/SDK
protocol APIs remain non-terminal.

Slice 1263 hard-cuts approval lease authority into Rust and deletes the JS
approval lease facade. `RuntimeApprovalStateCore` now expects the typed
`daemonCoreApprovalApi.authorizeApprovalRequest` and
`authorizeApprovalDecision` responses to carry Rust-authored `approval_lease`
records, lease ids, and lease statuses. Rust `approval.rs` owns the
`ioi.runtime.approval-lease.v1` record, hashes it into request/decision
authority records, includes it in request/decision/revoke state updates, and
rejects state planning when the authority record lacks the lease binding. The
public approval surface no longer normalizes decisions locally and no longer
authors lease ids, TTL/expiry facts, policy hashes, or lease state; it simply
requires Rust authority output before persistence. `runtime-approval-lease.mjs`
and `runtime-approval-lease.test.mjs` are absent, and conformance now guards
their absence plus the Rust lease-binding API. Wallet.network grant issuance
semantics, richer authority projection/replay storage, and stable IDE/CLI/SDK
approval APIs remain non-terminal.

Slice 1264 retires the stale Agentgres MCP live-result pending-transport
fixture truth. Rust Agentgres MCP live-result state commit examples and protocol
tests now use `status: "rust_materialized"`, `result_materialized: true`,
`backend_materialization_status: "rust_driver_contract_bound"`, and no retired
command/binary/compatibility fallback proof fields. Conformance now scans the
Rust Agentgres admission/protocol cores so `admitted_pending_rust_transport`
cannot remain accepted live-result commit truth. Broader non-MCP SDK
route-family protocol coverage over Rust replay records remains non-terminal.

Slice 1330 hard-cuts the model_mount runtime preference/profile JS cache
substrate. `ModelMountingState` no longer constructs `runtimeSelections` or
`runtimeEngineProfiles`, `MODEL_MOUNTING_STATE_MAPS` no longer loads
`runtime-preferences` or `runtime-engine-profiles`, the store no longer creates
those local cache directories, and focused state/store/read-projection tests
assert the cache fields and dirs are absent. Runtime-engine selection/profile
truth remains Rust-owned through typed `planModelMountRuntimeEngine`, Agentgres
`runtime-engine-controls` record commits, and Rust read-projection replay over
runtime `state_dir`. Local runtime materialization and stable IDE/CLI/SDK
runtime-engine APIs remain non-terminal; the retired JS preference/profile maps
must not return as empty compatibility state or duplicate projection truth.

Slice 1331 hard-cuts the model_mount MCP server JS cache substrate.
`ModelMountingState` no longer constructs `mcpServers`,
`MODEL_MOUNTING_STATE_MAPS` no longer loads `mcp-servers`, the store no longer
creates that local cache directory, and focused MCP/state/store tests assert
the cache field and dir are absent. MCP import, ephemeral registration, tool
invoke, workflow-node execution, and server list truth remain Rust-owned through
typed `planModelMountMcpWorkflow`, Agentgres `mcp-servers` record commits,
materialized MCP workflow receipts, and Rust `mcp_servers` read-projection
replay over runtime `state_dir`. Live external MCP transport/discovery and
stable IDE/CLI/SDK MCP APIs remain non-terminal; the retired JS `mcpServers`
map must not return as empty compatibility state or duplicate MCP projection
truth.

Slice 1332 hard-cuts the model_mount conversation JS cache substrate.
`ModelMountingState` no longer constructs `conversations`,
`MODEL_MOUNTING_STATE_MAPS` no longer loads `model-conversations`, response-id
collision checks and previous-response lookup now read the Rust
`model_conversation_states` projection, and Rust-authored conversation-state
commits no longer repopulate a local JS map. Conversation truth remains
Rust-owned through typed conversation/stream plans, Agentgres
`model-conversations` commits, receipt/state-root binding, and Rust replay over
runtime `state_dir`. Hosted/stream protocol parity and stable IDE/CLI/SDK
conversation APIs remain non-terminal; the retired JS `conversations` map must
not return as empty compatibility state or duplicate response-lineage truth.

Slice 1333 hard-cuts the model_mount catalog-search last-search JS cache slot.
`ModelMountingState` no longer constructs `lastCatalogSearch`, catalog-search
tests no longer preserve a null or fixture cache slot, and the direct
read-projection fixture no longer transports stale last-search state. Public
catalog search remains Rust-owned through the `catalog_search` read projection
over Agentgres provider-inventory replay; JS provider iteration, result
aggregation, enrichment, and last-search cache compatibility must not return.

Slice 1334 hard-cuts the model_mount vault-ref JS cache substrate.
`ModelMountingState` no longer constructs `vaultRefs`, the state map loader no
longer hydrates `vault-refs` into JS memory, and daemon startup no longer loads
that map back into the local vault port as accepted metadata. Public vault
bind/list/metadata/status/health/remove truth remains Rust-owned through
`planModelMountVaultControl`, Agentgres `vault-refs` commits, wallet.network
authority evidence, cTEE custody evidence, and Rust custody replay. The
`vault-refs` record directory remains the admitted Agentgres substrate; the
retired JS `vaultRefs` map must not return beside it.

Slice 1335 hard-cuts the model_mount download JS cache substrate.
`ModelMountingState` no longer constructs `downloads`,
`MODEL_MOUNTING_STATE_MAPS` no longer hydrates `model-downloads` into JS
memory, and the store no longer precreates a local `model-downloads` cache
directory. Public download queue/cancel/status/list truth remains Rust-owned
through `planModelMountStorageControl`, Agentgres `model-downloads` commits,
and Rust storage read-projection replay. The `model-downloads` record directory
remains an admitted Agentgres substrate created by record-state commits; the
retired JS `downloads` map must not return beside it.

Slice 1336 hard-cuts the model_mount route JS cache substrate.
`ModelMountingState` no longer constructs `routes`,
`MODEL_MOUNTING_STATE_MAPS` no longer hydrates `model-routes` into JS memory,
default route templates are no longer seeded into a local JS route map, and the
store no longer precreates a local `model-routes` cache directory. Public route
write/test/selection truth remains Rust-owned through `planModelMountRouteControl`,
Agentgres `model-routes`, `model-route-selections`, and
`model-route-endpoint-resolutions` commits, plus Rust read-projection replay
over runtime `state_dir`. The `model-routes` record directory remains an
admitted Agentgres substrate created by record-state commits; the retired JS
`routes` map must not return beside it as empty compatibility state or duplicate
route truth.

Slice 1337 hard-cuts the remaining model_mount topology JS cache substrate.
`ModelMountingState` no longer constructs `providers`, `artifacts`,
`endpoints`, or `instances`; startup no longer calls a local topology loader or
default topology seeder; `state-seeding.mjs` and its test are deleted;
`MODEL_MOUNTING_STATE_MAPS` is empty; the generic `loadModelMountingMap()`
loader is gone; the store no longer precreates local `model-providers`,
`model-artifacts`, `model-endpoints`, or `model-instances` cache directories;
and disabled-fixture cleanup no longer remains as JS topology-map pruning.
Public topology truth remains Rust-owned through typed
provider/artifact-endpoint/instance lifecycle plans, Agentgres record-state
commits, and Rust read-projection replay over runtime `state_dir`. The
`model-*` record directories remain admitted Agentgres substrates created by
record-state commits; local JS topology maps, default seeding, loader
compatibility, and fixture-prune truth must not return beside Rust replay.

Slice 1338 hard-cuts the model_mount canonical projection cache substrate.
`ModelMountingState` no longer exposes `canonicalProjectionWritePlan()` or
`writeProjection()`, daemon startup no longer materializes a canonical projection
file, Rust-authored receipt persistence no longer refreshes projection cache
JSON, and `AgentgresModelMountingStore` no longer exposes `writeProjection()` or
`readProjection()` or creates the local `projections/` directory. Runtime doctor
output now points to Rust model_mount read-projection ownership instead of the
old `model-mounting-canonical` file path. Public model_mount reads remain
Rust-owned through typed read-projection APIs over runtime `state_dir` and
Agentgres replay; the deleted local projection cache must not return as a
Rust-gated compatibility substrate, duplicate truth file, or diagnostic path.

Slice 1339 hard-cuts the model_mount local materialization cache directories.
`AgentgresModelMountingStore.ensureDirs()` no longer precreates local
`provider-health`, `backend-logs`, `server-logs`, `lifecycle-events`, or
`workflow-bindings` directories. Public provider-health, backend lifecycle/log,
server-control, lifecycle, and workflow-binding readback remains Rust-owned
through typed read-projection APIs over runtime `state_dir` plus Agentgres
record replay. The admitted Rust Agentgres record writers may still materialize
canonical record directories when committing records; the deleted JS-created
local materialization caches must not return beside Rust replay as duplicate
health, log, lifecycle, server, or workflow-binding truth.

Slice 1340 hard-cuts runtime projection bridge-shaped public API names.
Runtime tool catalog, repository workflow, and skill/hook registry projection
cores now expose positive Rust daemon-core request/error/result surfaces without
the old `BridgeRequest`, `CommandError`, or JS `BridgeResult` normalizer names.
`RuntimeToolCatalogProjectionRequest`, `RepositoryWorkflowProjectionRequest`,
and `SkillHookRegistryProjectionRequest` remain the public Rust projection
requests; `RuntimeToolCatalogProjectionError`, `RepositoryWorkflowProjectionError`,
and `SkillHookRegistryProjectionError` are the direct Rust errors; and the JS
policy client normalizers use positive projection-result names only. The retired
bridge-shaped request, command-error, and bridge-result names must not return as
compatibility aliases for these Rust-owned public projection families.

Slice 1341 hard-cuts runtime lifecycle projection bridge-shaped public API names.
The public lifecycle read projection family already routes through typed Rust
daemon-core projection over Agentgres `state_dir` replay; its Rust request/error
and JS protocol normalizer no longer carry bridge-shaped names. The public Rust
API is `RuntimeLifecycleProjectionRequest` and `RuntimeLifecycleProjectionError`,
and the JS protocol client uses `normalizeRuntimeLifecycleProjectionResult`.
`RuntimeLifecycleProjectionBridgeRequest`,
`RuntimeLifecycleProjectionCommandError`, and
`normalizeRuntimeLifecycleProjectionBridgeResult` must not return as lifecycle
projection compatibility aliases beside the Rust-owned replay projector.

Slice 1342 hard-cuts context/memory policy bridge-shaped public API names.
The context lifecycle and thread-memory policy families already enter Rust
through typed daemon-core APIs; their remaining adapter request/error/result
names no longer preserve bridge or command-transport shape. The Rust adapter
requests are `ContextBudgetPolicyApiRequest`, `CodingToolBudgetBlockApiRequest`,
`CompactionPolicyApiRequest`, `ContextCompactionPlanApiRequest`,
`ContextCompactionStateUpdateApiRequest`,
`MemoryManagerStatusProjectionApiRequest`,
`MemoryManagerValidationProjectionApiRequest`, and
`ThreadMemoryAgentStateUpdateApiRequest`; the shared adapter errors are
`ContextPolicyApiError` and `McpMemoryApiError`; JS protocol-client
normalizers use positive result names only. The retired bridge request,
command-error, bridge-result normalizer, `*_command` source marker, and
`*_command_response` helper/test names must not return for these Rust-owned
context-policy, compaction, memory-manager, and thread-memory state-update
surfaces.

Slice 1343 hard-cuts runtime memory projection/control bridge-shaped public API
names. Public memory read projection and memory mutation/control already enter
Rust through typed `daemonCoreThreadMemoryApi` methods with runtime `state_dir`
replay and Agentgres memory-state admission; their remaining Rust request/error,
JS normalizer, and source-marker names no longer preserve bridge or command
transport shape. The public Rust APIs are
`RuntimeMemoryProjectionApiRequest`, `RuntimeMemoryProjectionApiError`,
`RuntimeMemoryControlApiRequest`, and `RuntimeMemoryControlApiError`; the JS
protocol client uses `normalizeRuntimeMemoryProjectionResult` and
`normalizeRuntimeMemoryControlResult`; and Rust source markers use
`rust_runtime_memory_projection_api` and `rust_runtime_memory_control_api`.
The retired runtime memory `BridgeRequest`, `CommandError`,
`normalize*BridgeResult`, `_command` source-marker, and
`*_command_response` helper/test names must not return as compatibility aliases
beside the Rust-owned memory projection/control route family.

Slice 1344 hard-cuts workspace-trust control bridge-shaped public API names.
Workspace trust warning/acknowledgement control already enters Rust through the
typed `daemonCoreWorkspaceTrustApi.planWorkspaceTrustControlStateUpdate` API,
with Rust `state_dir` replay, event planning, and Agentgres runtime-event
admission before public truth can return. The remaining adapter request/error,
JS normalizer, and source-marker names now expose positive Rust daemon-core API
shape: `WorkspaceTrustControlStateUpdateApiRequest`,
`WorkspaceTrustControlApiError`,
`normalizeWorkspaceTrustControlStateUpdateResult`, and
`rust_workspace_trust_control_state_update_api`. The retired workspace-trust
`BridgeRequest`, `CommandError`, `normalize*BridgeResult`, `_command` source
marker, and `*_command_response` helper/test names must not return beside this
Rust-owned workspace-trust control route family.

Slice 1345 hard-cuts the runtime memory local cache substrate. Daemon startup no
longer constructs `AgentMemoryStore`, `memory-store.mjs` and its tests are
deleted, and the only remaining memory prompt parser lives in
`memory-command-parser.mjs`. Thread-memory state no longer exports private
cache-backed list/policy/path helpers or refreshes `store.memory` after Rust
Agentgres memory-state commits; public thread/agent list, policy, path, status,
and validation readback stays on `projectRuntimeMemoryProjection`. Thread
projection no longer reads the mounted memory projection as a JS side channel;
Slice 1346 moves memory counts into Rust state-dir replay. The retired `AgentMemoryStore`,
`this.memory`, `store.memory.*`, private thread-memory list/policy/path readers,
and temporary memory projection cache refresh must not return beside the
Rust-owned memory projection/control hot path.

Slice 1346 hard-cuts runtime thread/turn projection fact transport. Public
`threadForAgent()` and `turnForRun()` now send only projection kind, thread/run/
turn identity, event stream, schema, and runtime `state_dir` to
`projectRuntimeThreadTurnProjection`; JS no longer enumerates runs, projects
thread/run events, reads event replay caches, calculates latest sequence,
queries memory counts, gathers subagent ids, or shapes agent/run/runtime-control/
usage facts before Rust projection. Rust `RuntimeThreadTurnProjectionRequest`
requires `state_dir`, denies retired caller fact fields and aliases, replays
`agents/*.json`, `runs/*.json`, `memory-records/*.json`, `subagents/*.json`,
and runtime event projection/replay state itself through canonical snake_case
record fields only, then authors thread/turn records and projection hashes from
that Agentgres substrate. The retired JS fact bundle, replay-cache latest
sequence, memory-count side read, runtime identity override, camelCase replay
fallback, and compatibility projection shapers must not return beside the
Rust-owned thread/turn projection hot path.

Slice 1347 hard-cuts runtime MCP serve query/raw JSON-RPC transport
compatibility. SDK `threadMcpServeRpc()` no longer inherits MCP list query
options, no longer builds `mcpServeQuery()`, and rejects retired
`thread_id`/`agent_id`/`server_id`/source-mode query context before transport.
Public and runtime thread MCP serve routes now require the
`ioi.runtime.mcp-serve-client.v1` body envelope on
`/v1/threads/{thread_id}/mcp/serve`, reject query-carried serve context, and
reject raw JSON-RPC bodies instead of merging query facts into the Rust-owned
MCP serve context. The live daemon contract initializes and lists served tools
through the same stable body envelope used for tool calls, and conformance
guards that the retired SDK query builder, query context merge, top-level serve
transport, and raw JSON-RPC compatibility path cannot return.

Slice 1348 hard-cuts stable model_mount read protocol clients. Public
`/v1/models/{id}`, `/v1/models/artifacts`, `/v1/models/endpoints`,
`/v1/models/providers`, `/v1/models/routes`, and
`/v1/models/catalog/search` now call the mounted Rust-owned model_mount read
projections for model-detail, artifact, endpoint, provider, route, and
catalog-search truth. SDK clients expose
`listModelArtifacts()`, `listModelEndpoints()`, `listModelProviders()`,
`listModelRoutes()`, and `searchModelCatalog()` over those stable protocol
routes, while CLI `models ls`, `models get`, `models capabilities`,
`models catalog-search`, and `routes ls` no longer use the older `/api/v1`
model_mount read URLs.
Conformance guards the stable route surface, SDK methods, CLI read-command
URLs, and the absence of the retired client read fallbacks for migrated read
commands. This remains non-terminal because hosted/provider materialization,
live cTEE secret injection into outbound hosted network requests, live external backend binary spawning/supervision,
the invocation-authority blocker superseded by Slice 1381, later stable IDE and SDK control-client rows still need terminal Rust-owned materialization and replay records.

Slice 1349 retires the legacy model_mount native read aliases for the migrated
stable read family. The daemon no longer routes `GET /api/v1/model-capabilities`,
`GET /api/v1/models/catalog/search`, `GET /api/v1/models/artifacts`,
`GET /api/v1/models/routes`, `GET /api/v1/models/{id}`,
`GET /api/v1/providers`, or `GET /api/v1/routes` to model_mount projection
methods; those reads must use the stable `/v1` protocol routes from Slice 1348.
Focused native-route tests assert the retired aliases return `not_found` without
calling `catalogSearch()`, `getModel()`, `listArtifacts()`,
`listModelCapabilities()`, `listProviders()`, or `listRoutes()`. Conformance
source-scans keep the removed GET handlers absent. This remains
non-terminal because mutation/control routes, live external backend binary spawning/supervision,
hosted/provider transport, live cTEE secret injection into outbound hosted network requests, invocation
authority depth, and later stable client protocol rows had not yet landed at that cut.

Slice 1350 hard-cuts stable model_mount receipt protocol clients and retires the
native receipt read aliases. Public receipt list/get/replay now use
`GET /v1/model-mount/receipts`, `GET /v1/model-mount/receipts/{id}`, and
`GET /v1/model-mount/receipts/{id}/replay` over the mounted model_mount
receipt store and Rust `receipt_replay` read projection; CLI receipt commands
and current proof/autopilot scripts consume those stable protocol routes.
`GET /api/v1/receipts`, `GET /api/v1/receipts/{id}`, and
`GET /api/v1/receipts/{id}/replay` are no longer routed by the native
model_mount handler, focused route tests assert those aliases return `not_found`
without calling receipt methods, and conformance scans keep clients and handlers
off the retired `/api/v1/receipts` family. This remains non-terminal because
mutation/control routes, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable client protocol rows had not yet landed at that cut.

Slice 1351 hard-cuts stable model_mount read proof and IDE clients. Current
proof/autopilot scripts, product UI/desktop/workbench clients, and IDE
workflow model-capability binding surfaces no longer name retired
`/api/v1/model-capabilities`, `/api/v1/models/catalog/search`,
`/api/v1/models/artifacts`, or `/api/v1/models/routes` read URLs; they use
`/v1/model-capabilities`, `/v1/models/catalog/search`, and the other stable
`/v1` model read protocols from Slice 1348. The workbench proof route scanner
now checks stable public read routes separately from the still-native
mutation/control aliases, and conformance scans CLI/SDK/proof/IDE client
surfaces plus product source-only clients so the retired read clients cannot
return. This remains non-terminal because mutation/control routes, backend
execution/materialization, hosted/provider transport, OAuth/auth-header
materialization, the invocation-authority blocker later superseded by Slice 1381, and later stable client protocol rows had not yet landed at that cut.

Slice 1352 hard-cuts stable model_mount operational read clients and retires
the native read aliases for that family. Public server status/logs/events,
backend list/logs, runtime-engine list/detail, instance list/loaded, and
authority snapshot reads now use `/v1/model-mount/*` stable daemon protocol
routes over the mounted Rust-owned model_mount read projections. CLI server,
backend, model `ps`, current proof scripts, product UI/desktop clients, and IDE
authority-binding surfaces moved off the older native read URLs. The daemon no
longer exposes `GET /api/v1/server/status`, `GET /api/v1/server/logs`,
`GET /api/v1/server/events`, `GET /api/v1/models/server`,
`GET /api/v1/backends`, `GET /api/v1/backends/{id}/logs`,
`GET /api/v1/models/backends`, `GET /api/v1/runtime/engines`,
`GET /api/v1/runtime/engines/{id}`, `GET /api/v1/models/runtime-engines`,
`GET /api/v1/models/instances`, `GET /api/v1/models/loaded`, or
`GET /api/v1/authority` as native read aliases. The generic
`GET /api/v1/models/:id` detail handler is retired as part of the stable
`GET /v1/models/{id}` read protocol. Conformance scans source-only clients and
focused route tests so these retired read aliases cannot return. This remains
non-terminal because mutation/control routes, live external backend binary spawning/supervision,
hosted/provider transport, live cTEE secret injection into outbound hosted network requests, invocation
authority depth, and later stable control-client rows had not yet landed at that cut.

Slice 1353 hard-cuts stable model_mount server-control protocol clients and
retires the native server-control aliases. Public server start/stop/restart now
use `POST /v1/model-mount/server/start`, `POST /v1/model-mount/server/stop`,
and `POST /v1/model-mount/server/restart`, authorize `server.control:*`, and
return mounted Rust daemon-core server-control records through the same
Agentgres-admitted server-control planner used by the prior record-state cut.
CLI server controls, current proof scripts, product UI actions, and daemon
contract tests moved off `POST /api/v1/server/start`,
`POST /api/v1/server/stop`, `POST /api/v1/server/restart`,
`POST /api/v1/models/server/start`, and `POST /api/v1/models/server/stop`.
The daemon native handler no longer exposes those aliases, focused route tests
assert they return `not_found` without calling server-control methods, and
conformance scans client surfaces so the retired control compatibility path
cannot return. At this cut the migration remained non-terminal because backend
execution/materialization, hosted/provider transport, OAuth/auth-header
materialization, the invocation-authority blocker later superseded by Slice 1381, and later stable control-client
rows had not yet landed.

Slice 1354 hard-cuts stable model_mount backend-control protocol clients and
retires the native backend lifecycle control aliases. Public backend
health/start/stop now use `POST /v1/model-mount/backends/{id}/health`,
`POST /v1/model-mount/backends/{id}/start`, and
`POST /v1/model-mount/backends/{id}/stop` over the mounted Rust daemon-core
backend-lifecycle planner and Agentgres record-state commit path. CLI backend
controls, current proof scripts, product UI/desktop probes, live-provider gates,
and daemon contract tests moved off `POST /api/v1/backends/{id}/health`,
`POST /api/v1/backends/{id}/start`, and
`POST /api/v1/backends/{id}/stop`. The daemon native handler no longer exposes
those aliases, focused route tests assert they return `not_found` without
calling backend lifecycle methods, and conformance scans client surfaces so the
retired backend-control compatibility path cannot return. This remains
non-terminal because live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1355 hard-cuts stable model_mount runtime-control protocol clients and
retires the native runtime survey/select/profile aliases. Public runtime
survey, selection, engine select-by-id, engine profile update, and profile
remove controls now use `POST /v1/model-mount/runtime/survey`,
`POST /v1/model-mount/runtime/select`,
`POST /v1/model-mount/runtime/engines/{id}/select`,
`PATCH /v1/model-mount/runtime/engines/{id}`, and
`DELETE /v1/model-mount/runtime/engines/{id}` over the mounted Rust
daemon-core runtime-survey/runtime-engine planners and Agentgres receipt or
record-state commit paths. CLI backend runtime controls, daemon contract tests,
validation proofs, product UI actions, and workbench route proofs moved off
`POST /api/v1/runtime/survey`, `POST /api/v1/runtime/select`,
`POST /api/v1/runtime/engines/{id}/select`,
`PATCH /api/v1/runtime/engines/{id}`, and
`DELETE /api/v1/runtime/engines/{id}`. The daemon native handler no longer
exposes those aliases, focused route tests assert they return `not_found`
without calling runtime-control methods, and conformance scans source clients so
the retired runtime-control compatibility path cannot return. This remains
non-terminal because model import/download/mount/load/unload, provider/vault/
catalog OAuth controls, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1356 hard-cuts stable model_mount route-control protocol clients and
retires the native route write/test control aliases. Public route upsert and
route test now use `POST /v1/model-mount/routes` and
`POST /v1/model-mount/routes/{id}/test` over the mounted Rust daemon-core
route-control planner and Agentgres record-state commit path, preserving
`route.write:*` and `route.use:{id}` authority gates at the stable protocol
edge. CLI route tests, live/provider gates, desktop probes, validation proofs,
production polish and IDE-launch scripts, product UI route actions, and
inference harnesses moved off `POST /api/v1/routes` and
`POST /api/v1/routes/{id}/test`. The daemon native handler no longer exposes
those aliases, focused route tests assert they return `not_found` without
calling route-control methods, and conformance scans source clients so the
retired route-control compatibility path cannot return. This remains
non-terminal because model import/download/mount/load/unload, provider/vault/
catalog OAuth controls, live external backend binary spawning/supervision, hosted/provider
transport, live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and
later stable control-client rows had not yet landed at that cut.

Slice 1357 hard-cuts stable model_mount lifecycle protocol clients and retires
the native model import/mount/load/unload aliases. Public model artifact import
now uses `POST /v1/model-mount/artifacts/import`; endpoint mount, endpoint
load/unload, and endpoint unmount now use `POST /v1/model-mount/endpoints`,
`POST /v1/model-mount/endpoints/{id}/load`,
`POST /v1/model-mount/endpoints/{id}/unload`, and
`DELETE /v1/model-mount/endpoints/{id}`; instance load/unload now use
`POST /v1/model-mount/instances/load`,
`POST /v1/model-mount/instances/unload`, and
`POST /v1/model-mount/instances/{id}/unload`; estimate-only model load now uses
the same stable endpoint/instance load routes with canonical
`load_options.estimate_only`. These stable protocol routes run over the mounted
Rust daemon-core artifact-endpoint and instance-lifecycle planners, preserve
the `model.import:*`, `model.mount:*`, `model.unmount:*`, `model.load:*`, and
`model.unload:*` authority gates, and return Agentgres record-state truth. CLI
lifecycle commands, IDE workbench actions, validation proofs, live-provider
gates, production-polish scripts, product UI lifecycle actions, and inference
harnesses moved off `POST /api/v1/models/import`,
`POST /api/v1/models/mount`, `POST /api/v1/models/estimate-load`,
`POST /api/v1/models/mounts`,
`POST /api/v1/models/mounts/{id}/load`,
`POST /api/v1/models/mounts/{id}/unload`,
`DELETE /api/v1/models/mounts/{id}`,
`POST /api/v1/models/instances/{id}/unload`,
`POST /api/v1/models/load`, and `POST /api/v1/models/unload`. The daemon native
handler no longer exposes those aliases, focused route tests assert they return
`not_found` without calling lifecycle methods, and conformance scans source
clients so the retired lifecycle compatibility path plus retired camelCase
load-policy/load-option request selectors cannot return. This remains
non-terminal because model download/storage controls, provider/vault/catalog
OAuth controls, live external backend binary spawning/supervision, hosted/provider transport,
live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and broader
later stable control-client rows had not yet landed at that cut.

Slice 1358 hard-cuts stable model_mount storage-download protocol clients and
retires the native catalog import-url, model download, artifact delete, and
storage cleanup aliases. Public catalog import-url now uses
`POST /v1/model-mount/catalog/import-url`; model download queue/status/cancel
now uses `POST /v1/model-mount/downloads`,
`GET /v1/model-mount/downloads/{id}/status`, and
`POST /v1/model-mount/downloads/{id}/cancel`; storage cleanup now uses
`POST /v1/model-mount/storage/cleanup`; artifact delete now uses
`DELETE /v1/model-mount/artifacts/{id}`. These stable protocol routes run over
the mounted Rust daemon-core storage-control planner and Agentgres record-state
commit path, preserving `model.download:*`, `model.import:*`, and
`model.delete:*` gates at the stable protocol edge. CLI storage/download
commands, validation proofs, live-provider gates, desktop probes, daemon
contract tests, product UI storage/download actions, and workbench command
tests moved off `POST /api/v1/models/catalog/import-url`,
`POST /api/v1/models/download`, `GET /api/v1/models/download/status/{id}`,
`POST /api/v1/models/download/{id}/cancel`,
`POST /api/v1/models/download/cancel/{id}`,
`POST /api/v1/models/storage/cleanup`, and
`DELETE /api/v1/models/{id}` for artifact delete. The daemon native handler no
longer exposes those aliases, focused route tests assert they return
`not_found` without calling storage/download methods, and conformance scans
source clients so the retired storage/download compatibility path cannot
return. This remains non-terminal because provider/vault/catalog OAuth
controls, live external backend binary spawning/supervision, hosted/provider transport,
live cTEE secret injection into outbound hosted network requests, the invocation-authority blocker later superseded by Slice 1381, and broader
later stable control-client rows had not yet landed at that cut.

Slice 1359 hard-cuts stable model_mount provider-vault-token-catalog protocol
clients and retires the native provider, vault, token, and catalog-provider
control aliases. Public catalog-provider config and OAuth controls now use
`/v1/model-mount/catalog/providers/{id}` and
`/v1/model-mount/catalog/providers/{id}/oauth/{start,callback,exchange,refresh,revoke}`;
provider list/upsert/health/models/loaded/start/stop controls now use
`/v1/model-mount/providers*`; wallet vault refs/status/health controls now use
`/v1/model-mount/vault/*`; and capability-token list/create/revoke plus token
count now use `/v1/model-mount/tokens*`. These stable protocol routes preserve
the provider, vault, provider-control, and tokenizer authority gates at the
daemon protocol edge while forwarding into the mounted Rust daemon-core
model_mount control/projection APIs and Agentgres record-state truth. CLI
provider/vault/token commands, validation proofs, live-provider gates, product
UI actions, IDE workbench actions, and OAuth callback proofs moved off
`/api/v1/models/catalog/providers*`, `/api/v1/providers*`,
`/api/v1/vault*`, and `/api/v1/tokens*`. The daemon native handler no longer
exposes those aliases, focused route tests assert they return `not_found`
without calling provider/vault/token/catalog methods, and conformance scans
source clients so the retired compatibility path cannot return. This remains
non-terminal because live external backend binary spawning/supervision, hosted/provider
transport, live cTEE outbound injection depth, the invocation-authority blocker superseded by Slice 1381,
and later stable control-client rows had not yet landed at that cut.

Slice 1360 hard-cuts stable model_mount SDK control protocol clients. The
agent SDK now exposes named protocol-client methods for the full stable
model_mount control surface: route upsert/test, server start/stop/restart,
backend health/start/stop/logs, runtime survey/select/profile controls,
artifact import/delete, endpoint mount/unmount/load/unload, instance
load/unload, download/status/cancel, storage cleanup, catalog-provider config
and OAuth controls, capability tokens, vault refs/status/health, and provider
upsert/health/models/loaded/start/stop. These methods call only the stable
`/v1/model-mount/*` daemon protocol routes over the Rust-owned daemon-core
planners and Agentgres record/projection truth; the SDK source has no
authoritative `/api/v1` model_mount control request path, and focused SDK tests
drive the whole route family while asserting retired `/api/v1` control routes
do not return through the SDK. At this cut the migration remained non-terminal
because live external backend binary spawning/supervision, hosted/provider transport,
live cTEE outbound injection depth, the invocation-authority blocker later superseded by Slice 1381, and the
then-pending IDE control surface still needed terminal Rust-owned protocol
coverage.

Slice 1361 hard-cuts stable model_mount IDE control protocol clients. The agent
IDE now exports a full model_mount control route catalog and request builder for
route upsert/test, server start/stop/restart, backend health/start/stop/logs,
runtime survey/select/profile controls, artifact import/delete, endpoint
mount/unmount/load/unload, instance load/unload, download/status/cancel, storage
cleanup, catalog-provider config and OAuth controls, capability tokens, vault
refs/status/health, and provider upsert/health/models/loaded/start/stop. The
IDE protocol client builds only stable `/v1/model-mount/*` endpoints, rejects
retired camelCase model_mount control request aliases instead of translating
them, exports the surface through `@ioi/agent-ide`, and focused tests drive the
whole route family while asserting no `/api/v1` control path returns through the
IDE. Workbench actions remain stable protocol clients over the same daemon
routes. This remains non-terminal because live external backend binary spawning/supervision,
hosted/provider transport, live cTEE outbound injection depth, and
the invocation-authority blocker is superseded by Slice 1381.

Slice 1362 hard-cuts hosted provider env secret material fallback retirement.
Hosted provider default records no longer read provider API-key environment
variables to decide whether OpenAI, Anthropic, or Gemini providers are
configured. They publish wallet.network vault refs only, and the provider
registry rejects legacy plaintext secret arguments or camelCase `secretRef`
option shims instead of treating them as configuration. `AgentgresVaultPort`
no longer maps hosted provider vault refs to API-key environment aliases during
secret resolution; an env var can no longer become request-time hosted provider
material or a parallel custody truth path. Vault material must be explicitly
bound through the vault/material-adapter boundary, with plaintext persistence
remaining false and provider env fallback marked retired. Focused tests assert
hosted defaults stay blocked on vault refs, legacy plaintext helper inputs fail
closed, and env values do not resolve provider vault material. Conformance
guards the absence of provider API-key env aliases in the model_mount hosted
provider/vault path so the fallback cannot return. This remains non-terminal
because live external backend binary spawning/supervision, hosted/provider transport, live cTEE secret injection into outbound hosted network requests, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1363 deletes the backend-process supervisor facade stubs. The mounted
model_mount state no longer exposes `ensureBackendProcess()`,
`touchBackendProcess()`, `startBackendProcess()`,
`spawnBackendChildProcess()`, `stopBackendProcess()`, or
`backendProcessSnapshot()` as fail-closed JS compatibility surfaces. Public
backend health/start/stop/log/list paths already go through Rust daemon-core
backend-lifecycle planning, Agentgres record-state commits, and Rust
read-projection replay; this cut removes the leftover JS process-supervisor
method names and the `model_mount_backend_process_supervisor_retired` error
shim rather than preserving them as terminal scaffolding. Focused tests assert
the supervisor/snapshot methods are absent from the mounted facade while backend
lifecycle still commits Rust-authored records and backend logs still project
through Rust replay. Conformance now rejects restoring those method names or the
retired supervisor shim. This remains non-terminal because live external
backend binary spawning/supervision, hosted/provider transport, live cTEE
secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1364 deletes the mounted provider-driver factory facade stub. Provider
execution, provider lifecycle, provider inventory, and provider result admission
already flow through typed Rust daemon-core model_mount APIs and Agentgres
record-state commits; the mounted `ModelMountingState` no longer exposes
`driverForProvider()` as a fail-closed JS driver allocation path, and the
`model_mount_provider_driver_factory_retired` shim is gone. Focused provider
tests assert the facade is absent before any JS driver allocation can occur,
while lifecycle and inventory tests continue to prove fixture, native-local,
and hosted provider calls do not consult the inert JS driver sentinels.
Conformance now rejects restoring the method name, retired error code, or
provider-driver helper shim. This remains non-terminal because hosted/provider
transport, live external backend binary spawning/supervision, live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1365 deletes the mounted receipt-authoring facade stubs. The mounted
model_mount state no longer exposes `lifecycleReceipt()` or `receipt()` as
fail-closed JS receipt-authoring compatibility surfaces. Rust-authored receipt
persistence remains available only through `persistRustAuthoredReceipt()` and
`persistRustAuthoredReceiptWithCommit()`, which require Rust receipt-author
markers plus Agentgres receipt-state commit before receipt truth can return.
Focused receipt tests assert the old authoring methods are absent while receipt
reads still delegate to the canonical store and non-Rust receipt persistence
still fails closed. Conformance now rejects restoring those method names,
`model_mount_js_receipt_creation_retired`, or the lifecycle receipt JS facade
evidence shim. This remains non-terminal because hosted/provider transport,
live external backend binary spawning/supervision, live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1366 hard-cuts the public/runtime route store-core lifecycle fallback.
Public daemon request handling now receives the Rust `contextPolicyCore` as an
explicit request dependency from daemon service startup, and the public
doctor/computer-use/studio projections plus agent/thread/run lifecycle control
routes require that explicit core before any Rust projection or lifecycle
planner can execute. `runtime-route-handlers.mjs` no longer reads
`store.contextPolicyCore` for agent delete/status/run creation; focused route
tests remove `contextPolicyCore` from their store fixtures and pass the Rust
core explicitly. Conformance now rejects restoring `store.contextPolicyCore` or
`store?.contextPolicyCore` in the public/runtime route files and requires the
service-level explicit core handoff. This remains non-terminal because hosted
provider transport, live external backend binary spawning/supervision,
live cTEE secret injection into outbound hosted network requests. The invocation-authority blocker is superseded by Slice 1381.

Slice 1367 hard-cuts the hosted provider invocation JS backend predicate for
non-stream model invocation. This intermediate cut is now superseded by Rust
invocation authority planning: `invocation_authority.rs` builds the canonical
`ioi.model_mount.provider_invocation.v1` request with
`execution_backend: "rust_model_mount_hosted_provider"` for hosted provider
kinds such as OpenAI, Anthropic, Gemini, OpenAI-compatible, Ollama, vLLM,
llama.cpp, LM Studio, custom HTTP, and depin TEE instead of returning through a
JS unsupported-backend predicate. The Rust `provider_execution` owner receives
that hosted request through the direct API boundary. This cut was superseded by
the hosted transport-contract materialization cut below; live external hosted
API execution, live cTEE secret injection into outbound hosted network
requests, live external backend binary spawning/supervision, and the
invocation-authority blocker is superseded by Slice 1381.

Slice 1368 hard-cuts hosted provider invocation out of the generic unsupported
backend lane and into a Rust-owned wallet/vault/cTEE transport gate. Hosted
provider execution admission now carries redacted auth evidence from canonical
vault-ref configuration (`rust_model_mount_hosted_provider_auth_gate`,
`wallet_network_provider_vault_ref_bound`,
`ctee_hosted_provider_secret_not_exposed`, and a vault-ref hash) without
materializing plaintext or leaking the vault ref. Rust `provider_execution`
recognizes `rust_model_mount_hosted_provider` as a first-class hosted invocation
lane, validates the bound provider-execution record, requires wallet authority
grant/receipt refs plus hosted auth/cTEE evidence, and fails missing authority or
auth evidence with named Rust errors before execution. This remains
non-terminal because live cTEE secret injection into outbound hosted network requests, live external hosted API execution, live hosted streaming network I/O, actual Rust
live external backend binary spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1369 hard-cuts the hosted provider invocation temporary transport
boundary. The Rust `provider_execution` owner no longer returns a temporary
transport error after authority/auth validation. Hosted non-stream provider invocation now
materializes a Rust-owned `rust_model_mount_hosted_provider` result contract
with output text, token accounting, invocation hash, provider-auth evidence
refs, backend evidence refs, wallet transport authority evidence, cTEE
no-plaintext evidence, and a hosted auth-header materialization contract marker.
Rust provider-result admission now accepts hosted results only when the
execution backend is `rust_model_mount_hosted_provider`, the response kind is
`rust_model_mount.hosted_provider`, and the wallet/vault/cTEE plus hosted
transport materialization evidence is present; missing evidence or JS-observed
provider-result backends fail closed before accepted truth. Focused JS/Rust
tests and conformance require the positive hosted transport-contract path and
reject restoring the retired pending error. This remains non-terminal because
direct live external provider network I/O, live cTEE secret injection into
outbound hosted network requests, live hosted streaming network I/O, actual Rust
live external backend binary spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1370 hard-cuts hosted provider stream invocation out of the fail-closed
JS stream scaffold. Hosted stream request shaping now selects
`rust_model_mount_hosted_provider_stream` instead of returning
`model_mount_provider_invocation_rust_backend_required`; the Rust
`provider_execution/stream` owner validates the bound provider-execution
admission, wallet authority refs, and redacted vault/cTEE auth evidence before
materializing a Rust-owned hosted stream result contract. The stream result
binds output text, token accounting, stream chunks, invocation hash, provider
auth evidence refs, backend evidence refs, `rust_model_mount.hosted_provider.stream`,
and `rust_hosted_provider_stream_transport_materialized` evidence without
returning through JS provider drivers. Rust provider-result admission now
accepts hosted stream starts only when the execution backend is
`rust_model_mount_hosted_provider_stream`, `stream_status` is `started`, and the
wallet/vault/cTEE plus hosted stream transport materialization evidence is
present; JS-observed provider-result backends or missing hosted stream evidence
fail closed before accepted truth. Focused JS/Rust tests and conformance now
require the positive hosted stream path and reject restoring the old hosted
stream Rust-required fallback. This remains non-terminal because live hosted
network I/O, live cTEE secret injection into outbound hosted network requests,
live external backend binary spawning/supervision. The invocation-authority blocker is superseded by Slice 1381.

Slice 1371 hard-cuts hosted provider auth-header materialization into a Rust
daemon-core provider-auth materialization API. Provider upsert now calls
`planModelMountProviderAuthMaterialization` before provider-control truth can
commit; Rust `provider_auth_materialization` emits an Agentgres record under
`model-provider-auth-materializations` with wallet vault-ref binding, cTEE
outbound-header custody, redacted vault/header binding refs,
`auth_header_materialization_status: "rust_ctee_outbound_header_bound"`, and no
returned or persisted header value. Provider-control records bind the provider
to that materialization ref, hosted invocation/stream evidence carries
`rust_provider_auth_materialization_bound` plus
`hosted_provider_auth_header_materialized_by_rust`, and Rust provider
execution/result admission now rejects hosted truth without the bound
auth-materialization evidence. Focused JS/Rust tests and conformance guard the
positive typed API and reject restoring JS auth-header materializers or
command-shaped provider-auth materialization transport. This remains
non-terminal because live hosted network I/O, live cTEE secret injection into
outbound hosted network requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1372 hard-cuts model-load backend process materialization into a Rust
daemon-core API. `loadModel()` now calls
`planModelMountBackendProcessMaterialization` after Rust provider lifecycle
planning and before instance lifecycle truth can commit; Rust
`backend_process` emits an Agentgres `model-backend-process-materializations`
record with wallet backend-process authority, cTEE process custody, redacted
spawn-contract hash, `process_execution_owner:
"rust_daemon_core.model_mount.backend_process_materialization"`, and explicit
false markers for JS process supervision, command-transport spawn,
binary-bridge spawn, and compatibility spawn fallback. Rust instance lifecycle
`load` requests now require `backend_process_ref` and
`backend_process_materialization_hash`, and model-load record-state commits
write the backend-process materialization record before the model-instance
record. Focused JS/Rust tests and conformance require the positive typed API,
the Agentgres commit, the instance binding, and the absence of restored JS
child-process supervisor, command transport, or binary bridge spawn paths. This
remains non-terminal because live hosted network I/O, live cTEE secret
injection into outbound hosted network requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1373 hard-cuts hosted provider transport-input binding into the Rust
provider-invocation request contract. Hosted non-stream and stream invocation
requests now carry canonical `base_url`, `provider_auth_materialization_ref`,
`outbound_header_binding_ref`, and
`auth_header_materialization_status: "rust_ctee_outbound_header_bound"` fields
from admitted provider/endpoint records into `ModelMountProviderInvocationRequest`.
Rust `provider_execution` rejects hosted invocation before result materialization
unless the endpoint URL, wallet/cTEE auth-materialization refs, and outbound
header binding are present; Rust result hashes bind `base_url_hash` plus the
auth materialization refs, and evidence now records
`rust_hosted_provider_endpoint_url_bound` and
`ctee_outbound_header_binding_ref_bound`. Focused JS/Rust tests and conformance
guard that hosted invocation cannot rely on evidence-only auth claims or
JS-implied endpoint transport inputs. This remains non-terminal because live
hosted network I/O, live cTEE secret injection into outbound hosted requests,
live external backend binary spawning/supervision. The invocation-authority blocker is superseded by Slice 1381.

Slice 1374 hard-cuts hosted provider transport result binding into the Rust
provider-invocation and provider-result contract. Hosted non-stream and stream
provider results now carry Rust-authored `hosted_transport_request_ref`,
`hosted_transport_request_hash`, `hosted_transport_response_hash`, and
`hosted_transport_status: "rust_hosted_provider_transport_response_bound"`
fields, and Rust provider-result admission rejects hosted truth unless those
hashes and `rust_hosted_provider_transport_{request,response}_bound` evidence
are present beside the wallet/cTEE auth materialization evidence. The old
`deterministic_hosted_provider_output` helper and "Rust hosted provider
invocation contract" success text are retired from the Rust model_mount core, so
hosted success can no longer be proven by a loose deterministic message without
the Rust transport request/response binding. Focused JS/Rust tests and
conformance guard the hash fields, evidence refs, and retired helper/text. This
remains non-terminal because live hosted network I/O, live cTEE secret injection
into outbound hosted requests, live external backend binary
spawning/supervision, and the invocation-authority blocker is superseded by Slice 1381.

Slice 1375 hard-cuts backend-process supervision binding into the Rust
backend-process materialization and instance-lifecycle contract. Rust
`planModelMountBackendProcessMaterialization` now emits
`backend_supervision_ref`, `backend_supervision_hash`,
`backend_supervision_status`, `process_supervision_owner:
"rust_daemon_core.model_mount.backend_process_supervisor"`, and a
`supervision_contract` inside the Agentgres
`model-backend-process-materializations` record and public response. The
daemon facade validates those Rust-owned fields, requires
`rust_backend_process_supervision_bound`, and model-instance `load` requests now
fail closed unless they bind the backend supervision ref/hash/status beside
`backend_process_ref` and `backend_process_materialization_hash`. Focused
JS/Rust tests and conformance guard that a model load cannot fall back to the
old process-hash-only boundary or reintroduce JS child-process supervisor,
command-transport spawn, binary-bridge spawn, or compatibility-spawn truth.
This remained non-terminal at the cut because live hosted network I/O, live
cTEE secret injection into outbound hosted requests, backend launch/supervision
implementation,. The invocation-authority blocker is superseded by Slice 1381; backend launch/supervision is superseded by
Slice 1379 below.

Slice 1376 hard-cuts public backend lifecycle start onto the Rust
backend-process materialization/supervision contract. `startBackend()` now
requires a Rust `planModelMountBackendProcessMaterialization` record-state
commit before backend lifecycle truth can commit, resolves backend identity from
canonical request input or Rust backend read projection rather than a JS backend
registry, and forwards only the Rust materialization `backend_process_ref`,
`backend_process_materialization_hash`, `backend_supervision_ref/hash/status`,
and `process_supervision_owner` into the backend-lifecycle request. Rust
`plan_model_mount_backend_lifecycle` rejects `model_mount.backend.start`
without that process/supervision binding, records the binding in the
Agentgres `model-backend-lifecycle-controls` record/public response, and emits
`rust_backend_lifecycle_backend_process_materialization_bound`,
`rust_backend_lifecycle_backend_process_supervision_bound`, and
`backend_lifecycle_start_js_process_control_retired` evidence. Focused
JS/Rust tests and conformance guard the two-record start path, the direct typed
API normalizer, and the absence of restored JS process control. This remained
non-terminal at the cut because backend launch/supervision implementation and
the invocation-authority blocker is superseded by Slice 1381;
backend launch/supervision is superseded by Slice 1379 below, and the cTEE
egress resolver blocker is superseded by Slice 1380.

Slice 1377 hard-cuts hosted provider invocation off the deterministic Rust
transport-contract output and onto a Rust daemon-core live hosted transport
executor. `provider_execution` now uses blocking Rust `reqwest` POST execution
for hosted non-stream and hosted stream lanes, derives provider output from the
live response body, and sends only `provider_auth_materialization_ref`,
`outbound_header_binding_ref`, materialization status, and cTEE no-plaintext
custody headers across the egress boundary. The old hosted success-text path is
gone; focused Rust tests stand up a local HTTP server and assert the Rust core
performs `POST /v1/responses` with the cTEE/header-binding refs instead of
synthesizing output. Hosted result admission now requires
`rust_hosted_provider_live_network_io_executed`,
`rust_hosted_provider_transport_executor_owned`, and
`ctee_outbound_secret_injection_ref_bound` evidence beside the existing
transport request/response hashes, so evidence-only hosted result truth cannot
return. Focused JS/Rust tests and conformance guard the live executor evidence,
the cTEE ref-bound boundary, and the absence of the old deterministic hosted
success text. The cTEE egress resolver blocker is superseded by Slice 1380;
the invocation-authority blocker is superseded by Slice 1381.

Slice 1378 hard-cuts hosted provider stream semantics into the Rust daemon-core
transport owner. Hosted stream invocation no longer calls the non-stream hosted
transport body extractor and no longer slices a buffered hosted response into
deterministic stream frames. `provider_execution/stream` calls the Rust-owned
`hosted_provider_stream_transport_output` executor, sends the same
wallet/cTEE-bound no-plaintext custody headers with an event-stream accept
contract, parses SSE or newline-delimited JSON delta frames in Rust, rejects a
hosted stream response with no deltas, and emits IOI JSONL stream chunks from
those live deltas. Hosted provider-result admission now requires
`rust_hosted_provider_stream_live_chunks_executed`,
`rust_hosted_provider_stream_semantics_owned`, and
`rust_hosted_provider_stream_sse_chunks_bound` beside the existing hosted
transport hashes and cTEE binding evidence, so a hosted stream cannot be
admitted from generic network evidence or body-sliced compatibility output.
Focused Rust tests stand up a local SSE server and assert `POST /v1/responses`,
`Accept: text/event-stream`, cTEE/header-binding refs, live delta chunks, and
the stream evidence; JS protocol tests and conformance guard the result
admission shape and reject restoring `hosted_provider_transport_output(request)?`
inside the stream owner. The cTEE egress resolver blocker is superseded by Slice
1380; the invocation-authority blocker is superseded by Slice 1381.

Slice 1379 hard-cuts live backend-process launch and stop supervision into the
Rust daemon-core model_mount backend-process owner. Rust now exposes
`supervise_model_mount_backend_process` /
`daemonCoreModelMountApi.superviseModelMountBackendProcess` beside the existing
materialization API, keeps a Rust-owned child-process registry, launches
external backend binaries with `std::process::Command`, stops them through the
same Rust registry, and records no raw executable path, spawn args, or pid in
public protocol responses. Backend process materialization now binds the
executable hash, public `startBackend()` commits a Rust
`model-backend-process-supervisions` Agentgres record before lifecycle truth can
commit, public `stopBackend()` commits the Rust stop-supervision record before
backend lifecycle stop truth, and Rust `plan_model_mount_backend_lifecycle`
rejects start/stop lifecycle records without the live runtime
`backend_process_runtime_ref/hash/status` binding. Focused Rust tests start and
stop a live child handle, focused JS tests assert the materialize -> supervise
-> lifecycle commit order, and conformance rejects planner-only starts, JS
child-process supervision, command-transport spawn, binary-bridge spawn, and
compatibility-spawn fallback. The cTEE egress resolver blocker is superseded by
Slice 1380; the invocation-authority blocker is superseded by Slice 1381.

Slice 1380 hard-cuts hosted cTEE egress resolver binding into the Rust
daemon-core model_mount provider-auth and hosted transport owners. Rust
`plan_model_mount_provider_auth_materialization` now emits a redacted
`ctee_egress_resolver_ref`, `ctee_egress_resolver_hash`, and
`ctee_egress_resolution_status: rust_ctee_outbound_egress_resolved` alongside
the provider-auth materialization ref and outbound-header binding ref, records
`rust_ctee_egress_resolver_bound` and
`ctee_outbound_egress_resolver_depth_bound` evidence in the Agentgres
provider-auth materialization record, and provider-control preserves those
fields instead of re-materializing auth in JS. Rust hosted invocation and stream
execution now reject `rust_model_mount_hosted_provider*` requests without the
cTEE egress resolver binding, bind the resolver ref/hash/status into the hosted
transport request/response hashes, and send resolver identity headers without
returning plaintext secret material. Rust provider-result admission now requires
the resolver ref/hash/status and resolver evidence before hosted non-stream or
stream truth can be accepted. JS surfaces are only protocol shapers for these
fields; focused Rust/JS tests and conformance guard the missing-resolver Rust
error, hosted transport headers, provider-result admission fields, and the
absence of command/env or JS provider-auth fallback. The invocation-authority
blocker is superseded by Slice 1381.

Slice 1381 hard-cuts model_mount invocation authority planning into the Rust
daemon-core model_mount owner. Rust now exposes
`plan_model_mount_invocation_authority` /
`daemonCoreModelMountApi.planModelMountInvocationAuthority`, and the model
invocation hot path consumes Rust-authored plans for provider-execution
request shape, provider invocation or stream invocation request shape,
provider-result admission request shape, invocation-admission request shape,
accepted-receipt transition request shape, and receipt-binding StepModule
projection request shape. The production JS hot path no longer calls the old
JS contract constructors for those requests; it only gathers canonical
protocol facts, asks the Rust authority planner for each admitted operation,
and then commits through the existing Rust Agentgres admission, receipt
state-root, replay, and StepModule binding APIs. Hosted/cTEE transport fields
such as endpoint `base_url`, auth materialization refs, outbound-header
binding refs, hosted transport hashes, and cTEE egress resolver refs are
preserved through the JS protocol shaper so Rust provider-result admission
receives the same custody/transport bindings it must verify. Focused Rust and
JS tests cover provider-execution planning, receipt-binding StepModule
projection planning, invocation/stream operation ordering, and missing-plan
fail-closed behavior. Conformance now rejects a model invocation hot path that
returns to JS contract authoring, command/env fallback, binary bridge fallback,
or unguarded compatibility shape for provider execution, provider invocation,
provider-result admission, invocation admission, accepted receipt transition,
or receipt binding.

Slice 1382 deletes the production JS model_mount invocation contract helper
surface after Rust daemon-core parity is verified. `model-invocation-operations.mjs`
no longer exports or implements the old provider-execution, provider-invocation,
provider-stream-invocation, provider-result-admission, invocation-admission,
accepted-receipt-transition, receipt-binding, or provider-invocation
requires-Rust helper constructors/predicates. The public `invokeModel()` and
`startModelStream()` facades now have only one authoritative substrate: gather
canonical protocol facts, require `planModelMountInvocationAuthority()`, consume
the Rust-authored request for each operation, and fail closed before any
provider execution, Agentgres admission, receipt persistence, state-root
transition, replay, or StepModule projection can proceed without that Rust plan.
Focused tests use local test-only Rust-plan fixtures rather than a production JS
contract builder, assert the retired helper exports are absent, and prove the
facade fails closed when the Rust planner is missing. Conformance now rejects
restoring the helper export names, helper alias table, JS receipt-detail builder,
false-predicate exports, or old direct helper tests beside the Rust invocation
authority planner.

Slice 1383 deletes backend-process fallback-proof protocol fields from the
Rust daemon-core model_mount backend-process materialization and live
supervision contracts. Rust `backend_process.rs` no longer serializes
`retired_paths`, `js_process_supervisor`, `command_transport_spawn`,
`binary_bridge_spawn`, or `compatibility_spawn_fallback` fields in
backend-process materialization seeds, Agentgres records, supervision
contracts, public responses, or live-supervision records. The JS daemon facade
and direct model_mount core now reject those fields if a Rust plan attempts to
return them, while preserving positive evidence refs for the retired JS
supervisor, command-transport spawn, and binary-bridge spawn boundaries. Focused
Rust and JS tests assert absence/rejection, and conformance guards that the
old false-field compatibility proof cannot reappear beside the Rust
backend-process owner.

Slice 1384 hard-cuts stable model_mount snapshot, projection, MCP workflow,
and workflow-node protocol clients. Public daemon routes now expose
`GET /v1/model-mount/snapshot`, `GET /v1/model-mount/projection`,
`GET /v1/model-mount/mcp`, `POST /v1/model-mount/mcp/import`,
`POST /v1/model-mount/mcp/invoke`,
`POST /v1/model-mount/workflows/nodes/execute`, and
`POST /v1/model-mount/workflows/receipt-gate` over the mounted Rust-owned
model_mount read projection, MCP workflow, StepModule dispatch, and receipt-gate
planning surfaces. The older native aliases `GET /api/v1/models`,
`GET /api/v1/models/events`, `GET /api/v1/projections/model-mounting`,
`POST /api/v1/workflows/nodes/execute`,
`POST /api/v1/workflows/receipt-gate`, `POST /api/v1/mcp/import`, and
`POST /api/v1/mcp/invoke` no longer route through the daemon native handler or
product/proof/IDE clients. Rust `workflowBindings` projection records now
advertise the stable `/v1/model-mount/workflows/*` daemon API paths rather than
the retired `/api/v1/workflows/*` paths. Focused route tests assert the stable
routes call the Rust-owned model_mount methods and the retired aliases return
`not_found` without touching snapshot, projection, MCP, workflow, or receipt-gate
methods; conformance scans product/proof/SDK/CLI/IDE/workbench source clients so
the old aliases cannot return as client fallbacks.

Slice 1385 hard-cuts shipped workbench workflow-composer generated media. The
tracked `ioi-workbench` workflow-composer bundle and sourcemap have been
regenerated from the stable protocol client sources and refreshed
`@ioi/agent-ide` build output, so the shipped webview media now carries
`/v1/model-mount/projection` and
`/v1/model-mount/workflows/nodes/execute` instead of the retired
`/api/v1/projections/model-mounting` or `/api/v1/workflows/*` aliases. This
closes the stale generated-JS facade that could preserve split-brain route
behavior after source parity was verified. Conformance now scans the generated
workbench bundle, sourcemap, and available agent-IDE dist artifacts alongside
source clients, and it requires the stable generated bundle routes while
rejecting the retired aliases.

## Final Doctrine

Hypervisor is the product/control layer for private autonomous work. The
Hypervisor Daemon owns execution semantics and authority boundaries. The Default
Harness Profile is the daemon-executed loop-native orchestration profile. The
existing Rust/WASM workload/kernel substrate should become the authoritative
backend for admitted step and module execution. Agentgres records admitted
truth. wallet.network authorizes secrets, scopes, approvals, leases, and
declassification. Private Workspace backed by cTEE keeps protected plaintext out
of untrusted compute by default. Hypervisor IDE composes, governs, and replays
the same graph the daemon and kernel execute. IOI L1 receives only selected
public, economic, rights, dispute, registry, or cross-domain commitments.

In one line:

> **The daemon decides, the kernel executes, Agentgres admits, wallet.network
> authorizes, cTEE protects custody, and Hypervisor IDE makes the whole machine
> governable.**
