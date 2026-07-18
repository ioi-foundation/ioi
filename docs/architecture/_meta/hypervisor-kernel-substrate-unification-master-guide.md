# Hypervisor Kernel Substrate Unification Master Guide

Status: non-doctrinal implementation migration and evidence guide.
Scope: migration sequencing, implementation evidence, route-family cleanup, and
terminal conformance for convergence of the Hypervisor daemon with the existing
Rust/WASM kernel/workload substrate.
Canonical owner: none. Architecture doctrine remains with the subject owners in
[`source-of-truth-map.md`](./source-of-truth-map.md) and the applicable ADRs.
Last alignment pass: 2026-07-11.
Doctrine status: reference
Implementation status: partial (the JS runtime daemon was retired and deleted 2026-06-23 — `1b68cca12`; Part I's split-brain evidence is preserved as PRE-RETIREMENT history; remaining route-family state in the migration matrix)
Implementation refs:
  - `crates/node/src/bin/hypervisor-daemon.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-12
Last pruning alignment: 2026-06-12. The migration matrix is now a compact macro
ledger; future guide updates should steer macro authority cuts instead of
per-slice evidence accumulation.

## How To Use This Guide

This guide has three jobs:

1. Restate the owner-defined target only as needed to interpret migration
   evidence for Hypervisor, the daemon, the Rust/WASM substrate, Agentgres,
   wallet.network, cTEE, Hypervisor Core, clients, and application surfaces.
2. Give implementers enough low-level structure to migrate the current repo
   without creating another split brain.
3. Record evidence and terminal conformance criteria for the implementation
   migration.

It owns no architecture doctrine and is not a release or work sequencer.
[`doctrine.md`](../components/daemon-runtime/doctrine.md) owns daemon execution
and the Step/Module ABI; [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
owns HarnessProfile semantics; [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
owns Hypervisor Core and Workflow Compositor shape; Agentgres, wallet.network,
and cTEE remain with their listed owners; ADR 0017 owns the no-duplicate-owner
decision. If a summary below conflicts with an owner document or ADR, the owner
wins and this guide must be corrected.

Read it by role:

| Reader | Start here | Then read |
| --- | --- | --- |
| System architect | Subject owners and ADRs | Use this guide only for migration evidence |
| Runtime implementer | Migration Baseline | Part III, Part IV, Part VII |
| Developer Workspace / workflow implementer | Migration Baseline | Part V, Part VI, Part VII |
| Agentgres / receipt implementer | Migration Baseline | Part III, Part IV |
| cTEE / private workspace implementer | Migration Baseline | Part II, Part III, Part VII |
| Migration lead | Migration Baseline | Part VII, Part VIII, Part IX |

The document is layered from high level to low level:

```text
Migration Baseline
  -> current split brain
  -> target ownership model
  -> Step/Module ABI
  -> truth, receipts, replay, and projections
  -> workflow compositor and Improvement Proposal Plane
  -> migration program and anti-patterns
```

Nothing here should be read as a request to create a second runtime beside the
daemon. The entire guide exists to converge the current product daemon and the
existing Rust/WASM kernel/workload substrate toward the execution architecture
defined by the subject owners.

The guide's terminal criteria are satisfied only when the migration evidence
passes the owner-defined conformance bar and the split brain no longer exists.
That statement records an implementation-evidence threshold; it does not let
this guide admit releases, order work, or override later owner decisions.

Historical slice notes below are retained only where they anchor existing
conformance evidence. They are not scheduling doctrine. New migration work
should update the compact matrix only when a macro authority boundary changes.

## Migration Baseline

This section is a non-normative synopsis of existing owner doctrine for reading
the implementation evidence below.

The long-term shape is not:

```text
Rewrite Hypervisor from scratch in Rust.
```

It is:

```text
Keep the Hypervisor Daemon as the product/control admission, enforcement, and
effect-execution boundary under applicable policy and authority.
Route consequential daemon steps through the existing Rust/WASM
kernel/workload substrate as the authoritative step/module execution backend.
Record admitted truth in Agentgres.
Authorize through local/domain governance and the applicable authority provider;
use wallet.network for portable delegation and designated high-risk effects.
Project the same graph into Developer Workspace, App/Web clients, and
CLI/headless projections; TUI remains an optional presentation over the
CLI/headless client.
Use cTEE Private Workspace profiles when untrusted compute must not receive
protected plaintext custody.
```

Short form:

```text
Hypervisor Daemon owns execution semantics.
Workflow Compositor shapes directed work.
Selected HarnessProfiles resolve scoped steps.
Default Harness Profile is reference/fallback.
Rust/WASM workload/kernel executes admitted step modules.
Agentgres records admitted domain operational truth and state roots.
Applicable local/domain policy and authority providers authorize;
wallet.network is mandatory for portable delegation and designated high-risk effects.
Hypervisor Core coordinates clients, application surfaces, sessions, and adapters.
Developer Workspace composes and inspects the same graph.
```

This guide is intentionally honest about what exists today versus what is the
target. It should prevent two common mistakes:

1. Treating the existing Rust/WASM substrate as irrelevant because the live
   product daemon is Node/JS.
2. Treating the Rust/WASM substrate as a peer runtime that replaces daemon
   admission, enforcement, and execution instead of sitting underneath them.

### End state in one diagram

```text
Hypervisor App / Hypervisor Web / CLI / SDK
  request, compose, inspect, approve, replay
        |
        v
Hypervisor Daemon
  admission, enforcement, and effect-execution boundary under applicable authority
        |
        v
Workflow Compositor
  high-level directed workflow/service graph and step contracts
        |
        v
Selected HarnessProfile
  step-resolution adapter; Default Harness Profile is reference/fallback
        |
        v
StepModuleRouter
  daemon-owned bridge from daemon loop steps to execution backends
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
  admitted domain operational truth and replay/restore record ownership
```

### Migration constraints

| Migration constraint | Owner-defined meaning applied to this migration |
| --- | --- |
| One execution owner | Hypervisor Daemon owns admission, enforcement, and execution semantics after applicable authorization. |
| One directed-work surface | Workflow Compositor owns high-level workflow/service graph shape and step contracts. |
| One step-resolution contract | HarnessProfiles resolve scoped steps under daemon gates; Default Harness Profile is the reference/fallback. |
| One step/module contract | Every serious step is represented as a `StepModuleInvocation` and result. |
| One admitted truth path | Agentgres admits meaningful operations, receipts, refs, heads, and state roots. |
| One migration direction | JS product paths converge into a Rust daemon core and Rust/WASM backend; obsolete shims are deleted after verification. |

### Concept ladder

| Layer | User sees | Implementer builds | Canon boundary |
| --- | --- | --- | --- |
| Product surface | Developer Workspace/App/Web/CLI/SDK workflow | workflow graph, approvals, replay, package UX | product requests and inspection only |
| Daemon admission and execution | a run that can act safely | gates, leases, StepModuleRouter, cTEE checks | applicable policy/authority authorizes; execution semantics live here |
| Workflow Compositor | directed workflow/service graph | step contracts, dependencies, review points, selection hints | high-level graph shape, not execution truth |
| Harness profile | scoped autonomous step | ActionProposal -> GateResult -> module execution -> observation | selected HarnessProfile resolves a step; DHP is reference/fallback |
| Execution backend | tool/model/worker/service progress | Rust/WASM service modules, workload jobs, model mounts, verifiers | backend executes admitted steps |
| Truth substrate | receipts, evidence, restore/replay | Agentgres operations, refs, heads, state roots | admitted operational truth |
| Settlement surface | marketplace/public/cross-domain proof when needed | L1/app-chain commitments by trigger | not default runtime settlement |

## Part I: Current Rust Baseline and Historical Split-Brain Evidence

This part separates current Rust source evidence from the pre-retirement
Node/JS split-brain record. Statements explicitly labeled historical describe
the deleted runtime daemon and must not be read as current implementation
status.

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

At the time of the split-brain analysis the repo also contained extensive
product-facing JS daemon infrastructure. Commit `1b68cca12` deleted that
package on 2026-06-23; none of the paths in the following table is current
implementation evidence. They remain only as historical rationale for the
migration:

| Retired area | Historical evidence | Migration lesson |
| --- | --- | --- |
| Node daemon package | `packages/runtime-daemon/package.json` is `@ioi/runtime-daemon`, ESM, Node >= 18. | The live product daemon was still Node/JS at analysis time (retired 2026-06-23). |
| HTTP daemon service | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs` creates an HTTP server and local state dir under `.ioi/agentgres`. | Product runtime control was then HTTP/JS, not native workload IPC by default (retired). |
| Tool dispatch | `packages/runtime-daemon/src/coding-tools.mjs` dispatches coding tools through JS functions such as `workspace.status`, `git.diff`, `file.apply_patch`, `test.run`, and `lsp.diagnostics`. | The then-live coding-agent step path was direct daemon-native JS tool execution (retired). |
| Approval routes | `packages/runtime-daemon/src/runtime-route-handlers.mjs` exposed thread approvals, tool invocation, events, replay, trace, and inspect routes. | These deleted JS handlers are migration history, not a current route surface. |
| Runtime event envelopes | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` mapped runtime events into workflow-node, component-kind, receipt-ref, artifact-ref, and policy-ref projections. | Useful projection concepts survived only where current Rust owners implement them; the deleted module owns nothing. |
| Model mounting | `packages/runtime-daemon/src/model-mounting/*` stores model artifacts, routes, providers, instances, vault refs, receipts, and projections. | Model mounting was then product-daemon state, with Agentgres-like receipt/operation hooks (retired; Rust owns it now). |
| Retired runtime-service command bridge | The old JS RuntimeAgentService command adapter, `RuntimeApiBridge` adapter surface, `runtime-api-bridge.mjs` module, `ioi-runtime-bridge` binary, bridge env policy overrides, and deleted runtime-service helper are retired. The daemon rejects `runtimeBridge` options. | Runtime-service execution must return through stable Rust daemon-core protocol/API ownership, not a revived Node command/env or binary bridge. |

The architecture docs already name the intended boundaries:

| Canon doc | Owner-defined boundary |
| --- | --- |
| `docs/architecture/components/daemon-runtime/default-harness-profile.md` | HarnessProfiles resolve scoped steps under daemon gates; Default Harness Profile is the reference scaffold/fallback. |
| `docs/architecture/foundations/domain-kernels.md` | IOI kernel / L0 substrate creates and operates many domain kernels and governed chains. |
| `docs/architecture/foundations/governed-autonomous-systems.md` | Serious autonomous systems are governed execution objects whose service modules produce receipted transitions. |
| `docs/architecture/components/daemon-runtime/private-workspace-ctee.md` | Private Workspace backed by cTEE is the daemon profile for no-plaintext-custody work on rented GPU nodes. |
| `docs/architecture/components/wallet-network/doctrine.md` | wallet.network owns authority, secrets, approvals, decryption leases, cTEE authority view, and capability exit authorization. |

### Current product runtime

Current product runtime is Rust:

```text
Developer Workspace (`Workbench` current-code alias) / Hypervisor App/Web /
Workflow Compositor projections and protocol clients
  -> crates/node hypervisor-daemon Axum routes
  -> Rust route owners under crates/node/src/bin/hypervisor_daemon_routes/
  -> RuntimeKernelService and subject-specific Rust service/kernel modules
  -> Agentgres-admitted records, receipts, replay, and owner projections
```

The deleted `packages/runtime-daemon` package, its stores, and
`RuntimeContextPolicyCore` are not live fallbacks. Current source still has
partial and unmounted Rust building blocks, stale protocol clients, and
route-family gaps; the migration matrix records those facts without treating
deleted JS as the current runtime or claiming terminal convergence.

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
| Improvement Proposal Plane for module/profile/schema/skill/memory changes | Implemented at the admission path: governed proposal admission requires eval/verifier receipts, approval, rollback, Agentgres binding, expected heads, and state roots; full review UI and live mutation commit remain product/runtime evolution. |

### Historical split-brain placement

The following diagram records the pre-retirement placement that motivated this
migration. It is historical evidence, not current runtime topology:

```text
Live product harness step:
  Node/JS daemon route -> JS tool function -> JS event/receipt/projection

Lower protocol step:
  Rust workload/control plane -> WASM service or workload job -> state root / receipt / block event
```

The owner-defined end state that replaced that split is a stable
daemon-to-kernel protocol surface, not a permanent bridge binary:

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

Historical slice note: Slices 924, 1232, and 1262 retired the
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
`workspace_root`, and `source_scope` into the manager normalizer without a
config-compatibility transport; MCP mutation/add helpers pass canonical
`workspace_root` and `source_scope`; `mcp-manager.mjs` no longer consumes
`sourcePath`, `sourceScope`, `config_compatibility`, or `configCompatibility`
from server config or context and no longer includes retired context
source/config aliases in evidence refs. This
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
envelopes. This removed JS calculation of readiness, issue counts, memory-key
counts, write-block reasons, routes, validation records, and evidence refs.
Slice 1403 supersedes the transitional JS memory-manager wrapper that Slice 786
left in place; do not restore it as terminal architecture.
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
store-owned subagent API with runtime `state_dir`; Rust replays admitted
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
admitted runtime-engine control truth. Command-transport replacement and stable
protocol APIs remain open; local runtime-engine helper materialization is
retired by Slice 1389.

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
no-commit planner success. Artifact delete and storage cleanup filesystem
custody now lives in Rust storage-control planning: Rust checks containment
under `storage_root`, hashes root/target refs, emits cTEE no-plaintext custody
evidence, and executes or dry-runs the mutation without returning plaintext
paths to JS. This remains non-terminal: richer catalog/download materialization
and stable protocol APIs remain required.

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
receipt/state-root binding beyond record-state commit, and stable protocol APIs
remain required. Delete/cleanup filesystem custody is handled by the later Rust
storage-control custody cut.

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
Slice 960 retired the old admission route pass-through wrappers for governed
improvement proposals, external capability exits, worker/service package
invocations, cTEE private workspace actions, and L1 settlement attempts. Slice
1429 later hard-deletes the route-visible JS surface shape for this cluster:
public thread admission routes enter through store-owned
`admitGovernedImprovementProposal()`,
`authorizeExternalCapabilityExit()`,
`admitWorkerServicePackageInvocation()`,
`executeCteePrivateWorkspaceAction()`, and `admitL1SettlementAttempt()` daemon
APIs, which delegate to internal Rust-backed product-route APIs. The mounted
delegate APIs are not public route facades and the old `*Surface` factories,
properties, and file paths stay absent. This does not claim terminal admission
migration: richer Rust daemon-core route admission, wallet.network authority,
cTEE custody enforcement, StepModuleRouter dispatch, Agentgres
expected-head/state-root binding, receipt/event materialization, replay,
projection, and stable SDK/IDE/CLI protocol APIs remain required before
terminal pure Rust substrate conformance.
Slice 961 retired the original daemon-store route pass-through wrappers for
workflow edit apply, diagnostics repair decision execution, workspace snapshot
list, and workspace restore preview/apply. Slice 1431 later supersedes that
temporary route-visible shape: workflow-edit proposal/apply, diagnostics repair
decision execution, workspace snapshot list, and workspace restore
preview/apply public thread routes enter through store-owned daemon methods
over internal Rust-backed delegate APIs. The mounted workflow-edit,
diagnostics-repair, and workspace-snapshot delegates are not public route
facades, and route handlers no longer call them directly. This does not claim
terminal workflow, diagnostics, or workspace-snapshot migration: deeper
workflow mutation custody, diagnostics/workspace replay and projection depth,
wallet/cTEE authority where applicable, Agentgres expected-head/state-root
binding, receipt/artifact materialization, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 962 retired the daemon-store approval route pass-through wrappers. At
that stage the public approval request, decision, approve/reject shortcut, and
revoke routes called the mounted fail-closed approval surface directly, so JS
no longer preserved `requestThreadApproval()`, `decideThreadApproval()`, or
`revokeThreadApproval()` as daemon-store compatibility wrappers. Slice 1430
later hard-deletes that route-visible surface shape by restoring store-owned
public approval API methods over an internal Rust-backed delegate. This does
not claim terminal approval authority migration: direct Rust daemon-core route
admission, wallet.network grant/lease issuance, Agentgres expected-head and
state-root binding, receipt/event materialization, replay, projection, and
stable SDK/IDE/CLI protocol APIs remain required before terminal pure Rust
substrate conformance.
Slice 963 retired the daemon-store context-policy route pass-through wrappers.
The public workflow-only context-budget, thread context-budget, thread
compaction-policy, thread compact, and run context-budget routes now enter
through store-owned context-policy API methods over the internal Rust-backed
delegate, so JS no longer preserves
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
At that point the public mode/model/thinking and workspace-trust
acknowledgement routes called the then-mounted `RuntimeThreadControl` delegate
directly, so JS no longer preserved
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
Slice 1439 later hard-deletes the route-visible thread-control surface shape.
Daemon startup now mounts `runtime-thread-control-api.mjs` as the internal
`threadControlApi` delegate, and public mode/model/thinking plus
workspace-trust acknowledgement routes enter through store-owned
`updateThreadMode()`, `updateThreadModel()`, `updateThreadThinking()`, and
`acknowledgeWorkspaceTrustWarning()` methods. Conformance guards the deleted
`runtime-thread-control-surface.mjs` files, the retired
`createRuntimeThreadControlSurface()` factory, the absent
`this.threadControlSurface` property, and direct `store.threadControlSurface.*`
route calls from returning beside the Rust-backed thread-control API.
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

Slice 901 deleted the unused local runtime-engine helper tail. Slice 1389
hard-deletes the remaining local runtime-engine helper module:
`local-runtime-engines.mjs` and `local-runtime-engines.test.mjs` are absent,
`model-mounting.mjs` no longer imports that module, and conformance now guards
that JS-side llama.cpp binary discovery/library-path materialization cannot
return beside Rust runtime-engine projection and backend-process planning.
Terminal runtime-engine migration still requires stable protocol APIs and
deeper replay/binding work, but not a JS local runtime materialization helper.

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

## Part II: Owner-Defined Target Execution Model

This part restates the desired ownership shape from the subject owner documents
for migration comparison. It records which implementation layer must converge,
how the Rust/WASM substrate sits under the daemon, and why the mature end state
is a Rust daemon core rather than a permanent JS execution substrate. It does
not independently define those ownership boundaries.

### Unified stack

```text
Hypervisor App / Hypervisor Web / CLI / SDK
  compose, inspect, approve, replay, package, and govern work

Hypervisor Daemon
  admission, enforcement, and effect-execution owner under applicable authority;
  local product control plane;
  implementation may begin as Node/JS facade, but mature daemon core should
  consolidate in Rust once the ABI and workload bridge prove parity

Workflow Compositor
  high-level directed workflow/service graph and step contracts

Selected HarnessProfile
  step-resolution adapter; Default Harness Profile is reference/fallback

StepModuleRouter
  daemon-owned bridge from daemon steps to execution backends

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
| User/operator UX | Hypervisor App / Web / CLI / SDK and Developer Workspace surfaces | Requests, displays, composes, steers, inspects. Does not own execution semantics. |
| Execution semantics | Hypervisor Daemon | The daemon admits or rejects proposed effect transitions under active policy and valid wallet.network grants; it does not originate authority. |
| Directed-work surface | Workflow Compositor | Shapes high-level workflow/service graphs, dependencies, review points, and step contracts. |
| Step-resolution profile | Selected HarnessProfile | Resolves scoped steps under daemon ownership; Default Harness Profile is reference/fallback. |
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

The applicable policy and authority provider authorize effects. The daemon owns
the admission, enforcement, and execution boundary; the Rust/WASM substrate
executes admitted module work and returns receipt-bound results.

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

Migration method:

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
Hypervisor App / Hypervisor Web / Developer Workspace
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
Hypervisor App/Web/Developer Workspace = TS/React or equivalent product UI
Hypervisor SDK = protocol bindings over Rust/core APIs
```

The JS facade is a migration scaffold, not a permanent authority layer. This is
an alpha-stage system with no downstream compatibility promise. Once the Rust
core owns the route family and the IDE/SDK can talk to it through stable
protocol APIs, the corresponding JS route should be removed or demoted into a
non-authoritative client adapter. Do not preserve legacy shims merely to keep old
callers alive.

## Part III: Step/Module ABI Migration Reference

This part is the implementation hinge. It mirrors the daemon-owned Step/Module
ABI from [`doctrine.md`](../components/daemon-runtime/doctrine.md#stepmodule-execution-abi)
so migration evidence can compare implementations. The daemon doctrine, not
this guide, defines the boundary that lets one daemon-owned loop step route to
Rust/WASM modules, workload jobs, model mounts, cTEE actions, verifiers, or
external capability exits without changing workflow or authority ownership.

### Purpose

The daemon-owned Step/Module ABI is the bridge between product-daemon loop
steps and kernel/workload execution; this guide records its migration use.

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
  context_cell_ref: context_cell://... | null

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

## Part V: Workflow Compositor Migration Evidence

This part summarizes migration evidence against the Workflow Compositor and
`WorkflowTemplate` contract owned by
[`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md).
It does not assign compositor ownership to Automations, Developer Workspace, or
Foundry and does not define another workflow graph object.

### Compositor purpose

The owner requires the Workflow Compositor to project an exact admitted
`WorkflowTemplate` revision and its execution evidence rather than become an
execution or truth owner. Automations may reference a template from
`AutomationSpec`; Developer Workspace and Foundry may consume contextual
projections. Those uses do not transfer compositor or graph-shape ownership.

It should show:

- workflow graph and node status;
- module kind and backend;
- authority scopes and approval gates;
- context cell and topology boundaries;
- artifact refs and payload refs;
- receipt timeline and replay availability;
- state-root/projection-watermark status;
- cTEE custody state and leakage profile;
- verifier status and unresolved uncertainty;
- package/module candidate status;
- upgrade proposals and eval gates.

### Governable graph evidence

This guide publishes no `WorkflowModuleGraph` schema. Migration evidence must
instead bind the owner-defined immutable `WorkflowTemplate` revision/hash,
typed nodes and edges, selected `HarnessProfile`, daemon-admitted backend and
authority facts, custody posture, expected receipts, execution result refs, and
Agentgres projection watermark. Any additional field belongs in the compositor
owner before implementation uses it.

### Trace-to-candidate evidence

The owner-defined improvement path treats successful traces as candidates, not
direct self-modifications:

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

### Migration-facing projection checks

| Projection check | Evidence expected by the subject owners |
| --- | --- |
| Graph view | module nodes, backend, status, dependencies, blockers. |
| Authority view | `scope:*`, `prim:*`, approvals, grants, step-up requirements, revocation. |
| Receipts view | ordered receipt timeline, evidence refs, state roots, verification status. |
| Context topology view | context cells, boundaries, compaction state, retrieval refs, private/public split. |
| cTEE view | plaintext-free runtime mount, custody type, leakage profile, declassification gates. |
| Replay view | deterministic replay sources, artifact refs, state roots, projection watermarks. |
| Package view | worker/service/module candidate, benchmark status, marketplace readiness. |

## Part VI: Improvement Migration Evidence

This part does not define an Improvement Proposal Plane or a proposal schema.
It summarizes migration evidence against `UpgradeProposalEnvelope` in
[`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md),
the bounded-improvement contracts in
[`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md),
and their existing Improvement, Evaluation, Governance, authority, and
Agentgres owners.

### Principle

Runtime evidence may support proposed changes to skills, memory, workflow
graphs, harness profiles, routes, verifiers, and modules. Only the
owner-defined proposal, evaluation, authority, admission, activation, and
rollback paths may make such a change live.

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

### Evidence inputs

The migration may demonstrate collection of:

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

### Candidate evidence categories

| Candidate | Examples |
| --- | --- |
| Skill candidate | repeated local troubleshooting sequence, repo-specific workflow, UI automation procedure. |
| Module candidate | verifier module, connector adapter, route selector, receipt writer, output checker. |
| Workflow candidate | PR creation workflow, quant backtest workflow, Discord moderation service flow. |
| Policy candidate | approval rule, cTEE declassification rule, route fallback rule, budget rule. |
| Schema candidate | `StepModuleInvocation` field addition, receipt schema, artifact projection. |
| Prompt candidate | model pass prompt, output ownership prompt, verifier prompt. |
| Route candidate | model mount route, worker package route, service package route. |

### Proposal binding

This guide publishes no `RuntimeImprovementProposal`. Implementation evidence
must bind the canonical `UpgradeProposalEnvelope` revision and target-owner
proposal path, with exact evidence, evaluation/verifier, authority, rollback,
expected-head, Agentgres operation, and activation refs required by those
owners. A missing target-owner resolver remains unavailable rather than
creating a guide-local proposal type.

### Required gates

The migration is not complete for an improvement path until owner conformance
proves that no candidate becomes live before:

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
compositor, cTEE, packages, the Improvement Proposal Plane, Rust core, facade
retirement, and full conformance.

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
- Hypervisor App/Web/CLI/SDK and Developer Workspace surfaces interact through stable protocol APIs instead of
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

hypervisor-conformance:app
  proves the Hypervisor app shell smoke, New Session harness/privacy gating,
  and provider operation proposal contract stay wired

hypervisor-conformance:compositor
  proves IDE workflow projections, replay metadata, and route-family status

hypervisor-conformance:negative
  proves forbidden bypasses fail closed
```

Terminal acceptance should cite the exact command names that exist in the repo.
The current command contract is implemented by
`scripts/conformance/hypervisor-conformance.mjs` and the
`hypervisor-conformance:*` npm scripts; Phase 11 remains incomplete only when
the terminal migration conditions fail, not because the command names are
missing.

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
- Confirm naming uses Hypervisor, Workflow Compositor, HarnessProfile, and
  Default Harness Profile only as the reference/fallback profile.

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
  context cell refs, and workflow projection metadata bind.

Likely files/modules:

- `crates/services/src/agentic/runtime/kernel/invocation.rs`
- `crates/services/src/agentic/runtime/harness.rs`
- `packages/runtime-daemon/src/runtime-event-envelopes.mjs`
- `packages/runtime-daemon/src/runtime-tool-api.mjs`
- `packages/hypervisor-workbench/src/runtime/harness-workflow/*`
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
Make Automations and its contextual Developer Workspace/Foundry compositor
views display the same substrate the daemon executes.

Implementation work:

- Add module backend, execution mode, state-root, receipt, artifact, custody,
  and authority metadata to workflow node projections.
- Add graph controls for projection/shadow/gated/live execution modes.
- Add cTEE/custody badges and declassification gates.
- Add receipt timeline and replay links per node.

Likely files/modules:

- the current `hypervisor-workbench` package name is an implementation alias
  during the Developer Workspace migration;
- `packages/hypervisor-workbench/src/runtime/harness-workflow/*`
- `packages/hypervisor-workbench/src/runtime/workflow-composer-model.ts`
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
- `packages/runtime-daemon/src/runtime-skill-hook-api.mjs`
- `packages/hypervisor-workbench/src/runtime/harness-workflow/*`

Conformance checks:

- no direct self-mutation;
- authority changes require approval;
- rollback refs exist.

Tests/proofs:

- failed-run candidate creation test.
- proposal gate test.
- rollback/revert test.

Risks:

- Improvement Proposal Plane becomes ungoverned prompt editing.

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
- `packages/hypervisor-workbench/src/*` client adapters;
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
Automations / Developer Workspace workflow
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
18. Treating this reference guide as architecture doctrine, release authority,
    or an autonomous sequencer instead of migration/evidence support for the
    existing owners.

## Part IX: Reference First Concrete Win

This historical reference milestone illustrated the smallest valuable proof of
the migration shape; it does not order current work or override the live
migration matrix.

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

Per-slice implementation narration (the current-lane notes and the
`Slice 1 → Slice 1440` ledger) is archived verbatim at
[`../_archive/change-ledgers/hypervisor-kernel-substrate-slice-ledger.md`](../_archive/change-ledgers/hypervisor-kernel-substrate-slice-ledger.md).

This guide now ends at the reference milestone and evidence baseline above. Current migration
state lives in the migration matrix (route-family owner map, macro
authority cut ledger, remaining terminal blockers); durable concept →
owner → form status lives in
[`implementation-matrix.md`](./implementation-matrix.md). New slices
append to git history and the matrices, not to this guide.
