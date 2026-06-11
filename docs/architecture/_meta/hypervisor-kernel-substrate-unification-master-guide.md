# Hypervisor Kernel Substrate Unification Master Guide

Status: implementation master guide.
Canonical intent: resolve the current Hypervisor daemon and Rust/WASM kernel/workload split brain without introducing a new runtime beside the daemon.
Primary owner candidate: architecture meta until promoted into component canon.
Last alignment pass: 2026-06-04.

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
| Retired runtime-service command bridge | The old JS RuntimeAgentService command adapter is retired; `RuntimeApiBridge` is injected-only and does not auto-configure command transport from env. | Runtime-service execution must return through stable Rust daemon-core protocol/API ownership, not a revived Node command bridge. |

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
| Daemon tool step routed through workload client into Rust/WASM service module | Current conformance requires `rust_workload_live` as the default StepModule runner, rejects explicit `daemon_js`, and removes the retired JS coding-tool dispatcher from live invocation. Remaining work is broader JS facade retirement around non-migrated route families. |
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

The current `ioi-step-module-bridge` command path is migration scaffolding for
the Node/JS facade while Rust ownership is being proven route by route; it must
not be treated as the terminal substrate. After parity is proven, the bridge
surface should either collapse into the Rust daemon core API or be renamed and
shrunk into a narrow daemon/kernel protocol transport with no independent
execution authority, no compatibility-shim semantics, and no duplicate truth
path. The target transport shape is a temporary transport to the Rust daemon core
with no independent authority or compatibility-shim behavior.

Current sprint note: Slice 924 retires the `IOI_STEP_MODULE_COMMAND_ARGS` and
constructor-`args` selectors at the runtime-daemon StepModule runner. The bridge
binary path may still exist as migration transport, but the JS edge may no
longer shape argv or preserve compatibility argument semantics; any direct Rust
daemon-core API that replaces this transport must keep that selector retired.
Slice 925 applies the same fixed-argv rule to the worker/service package, L1
settlement, cTEE private workspace, external capability authority, and governed
meta-improvement daemon-core runners by retiring `IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS`
and constructor-`args` for those surfaces. This is still not the terminal
transport shape: direct Rust daemon-core APIs must replace the command transport
after the relevant admission/control APIs are verified.
Slice 926 extends the fixed-argv rule to coding-tool approval, approval-state,
context-policy/state-update, runtime Agentgres admission, and workspace-restore
daemon-core runners. The remaining command-transport shape is still migration
scaffolding, not the target Rust daemon-core API.
Slice 927 extends the fixed-argv rule to the model_mount admission runner. The
JS edge can no longer use `IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS` or constructor
`args` to shape daemon-core argv for model_mount admission, provider execution,
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
Slice 751 retired the OpenAI-compatible stream cancellation JS receipt facade
before `model_invocation_stream_canceled` receipt construction; cancellation
now requires Rust `model_mount` stream lifecycle admission.
Slice 752 retired direct receipt-gate JS receipt construction before
`workflow_receipt_gate` or `workflow_receipt_gate_blocked` receipt creation;
receipt-gate admission now requires Rust daemon-core receipt binding and
Agentgres truth.
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
retirement compaction is complete. Slice 751 stream-cancel receipt facade
retirement compaction is complete. Slice 752 receipt-gate receipt facade
retirement compaction is complete. Slice 753 public model invocation dead JS
body-retirement compaction is complete. Slice 754 retired model invocation
migration-helper compatibility aliases and its compaction is complete. Slice
755 retired the daemon workflow-edit proposal/approval read-helper facades that
remained after workflow-edit apply authority was fail-closed. Workflow-edit
execution is still not terminal: approved apply still requires Rust daemon-core
mutation admission, Agentgres expected-head/state-root binding, receipt/event
materialization, projection, and replay before it can execute again. The Slice
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
projection, replay, SDK/IDE protocol coverage, and conformance. Do not encode
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
now also fails closed with `runtime_run_memory_mutation_rust_core_required` for
chat/API remember, edit, delete, enable, and disable mutation commands; read
injection and subagent memory inheritance remain projection adapters over
already-admitted memory. This does not claim terminal memory migration: direct
Rust daemon-core memory admission/projection still needs to own policy
authority, receipt/event materialization, Agentgres expected-head/state-root
binding, ArtifactRef/PayloadRef where needed, replay, SDK/IDE protocol coverage,
and conformance. Do not encode the remaining JS memory read adapter or
run-memory projection helper as terminal architecture.
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
receipt/event materialization, replay, SDK/IDE protocol coverage, and
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
binding, projection, replay, SDK/IDE protocol coverage, and conformance. Do not
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
expected-head/state-root binding, replay, SDK/IDE protocol coverage, and
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
projection, replay, SDK/IDE protocol coverage, and conformance. Do not encode
the remaining fail-closed JS artifact facade as terminal architecture.
The Slice 768 visual artifact path alias-retirement matrix-compaction pass is
complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 769 retired the MCP serve `tools/call` `params.args` fallback before
served runtime tool invocation input crosses into the daemon: at that slice,
the MCP serve surface consumes canonical MCP `params.arguments` only. Slice 955
later retired the remaining MCP serve JS tool-call dispatch path entirely, so
canonical `params.arguments` no longer crosses into JS `invokeThreadToolAsync`.
This does not claim terminal MCP serve migration: direct Rust daemon-core MCP
serve/control/admission/projection still needs to own wallet authority,
transport containment, StepModuleRouter dispatch, receipt binding, Agentgres
expected-head/state-root binding, projection, replay, SDK/IDE protocol coverage,
and conformance. Do not encode the remaining JS MCP serve protocol facade as
terminal architecture. The Slice 769 MCP serve `params.args` alias-retirement
matrix-compaction pass is complete.
Slice 770 retired the MCP manager `allowedTools` server config/catalog fallback
before MCP manager records can expose tools. `mcp-manager.mjs` now derives
declared tool exposure only from canonical `allowed_tools` and declared `tools`
object keys; retired `allowedTools` can no longer create catalog tool records or
suppress empty-allowed-tools warnings. This does not claim terminal MCP manager
migration: direct Rust daemon-core MCP control/admission/projection still needs
to own wallet authority, transport containment, StepModuleRouter dispatch,
receipt binding, Agentgres expected-head/state-root binding, registry truth,
replay, SDK/IDE protocol coverage, and conformance. Do not encode the remaining
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
replay, SDK/IDE protocol coverage, and conformance. Do not encode the remaining
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
SDK/IDE protocol coverage, and conformance. Do not encode the remaining JS MCP
manager/catalog helpers as terminal architecture. The Slice 773 MCP manager
validation secret-ref alias-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 774 moved public MCP server validation decisioning into Rust daemon-core
validation transport. `McpServerValidationCore` now owns validation status,
diagnostics, and warnings for normalized canonical MCP server records, the
daemon-core command bridge exposes `validate_mcp_servers`, and the runtime
daemon `validateMcp()` facade consumes `contextPolicyRunner.validateMcpServers`
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
records through `contextPolicyRunner.validateMcpServers({ servers })` so public
MCP status/validation pass-block decisions come from Rust
`McpServerValidationCore` via `validate_mcp_servers` migration transport. This
still does not claim terminal MCP migration: catalog normalization/projection,
registry truth, wallet authority, transport containment, receipt binding,
Agentgres admission, replay, and SDK/IDE protocol coverage still need direct
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
Agentgres admission, replay, and SDK/IDE protocol coverage still need direct
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
replay, and SDK/IDE protocol coverage still need direct Rust daemon-core
ownership. The Slice 779 MCP validation projection Rust-core matrix-compaction
pass is complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 780 moved public MCP declared catalog list/search row projection into Rust
daemon-core migration transport. `listMcpTools()`, `listMcpResources()`,
`listMcpPrompts()`, and declared-catalog `searchMcpToolCatalog()` now consume
`McpManagerCatalogProjectionCore` / `plan_mcp_manager_catalog_projection`
instead of calling JS `mcpToolsForServers`, `mcpResourcesForServers`, or
`mcpPromptsForServers` row builders; live discovery results are normalized back
through the same Rust catalog projection before search/fetch response filtering.
This still does not claim terminal MCP migration: direct Rust daemon-core MCP
registry truth, live transport discovery and containment, wallet authority,
StepModuleRouter dispatch, receipt binding, Agentgres admission, replay, and
SDK/IDE protocol coverage still need direct Rust daemon-core ownership. The
Slice 780 MCP public catalog Rust-core matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 781 moved MCP catalog summary projection into Rust daemon-core migration
transport. `searchMcpToolCatalog()` still performs live MCP transport discovery
in JS during migration, but declared and live-discovered tool/resource/prompt
rows now pass through `McpManagerCatalogSummaryProjectionCore` /
`plan_mcp_manager_catalog_summary_projection` before public search/fetch
responses expose `ioi.runtime_mcp_catalog_summary` records; the JS catalog
surface no longer imports, injects, or calls `mcpCatalogSummaryForServer()` for
those public summaries. This still does not claim terminal MCP migration:
direct Rust daemon-core MCP registry truth, live transport discovery and
containment, wallet authority, StepModuleRouter dispatch, receipt binding,
Agentgres admission, replay, and SDK/IDE protocol coverage still need direct
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
SDK/IDE protocol coverage still need direct Rust daemon-core ownership. The
Slice 782 MCP helper summary-retirement matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands.
Slice 783 retired the dead helper-level JS MCP mutation/registry projection
path. `runtime-mcp-helpers.mjs` no longer exports
`mcpRegistryWithServers()`, `mcpServerRecordsFromMutationInput()`,
`mcpServerRecordFromAddRequest()`, `mcpResourceKey()`, or `mcpPromptKey()`;
helper tests no longer preserve those JS import/add/registry projection bodies
after public MCP control mutations already fail closed and validation/catalog
projection routes through Rust daemon-core migration transport. This still does
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
JS transport wrapper around `contextPolicyRunner.projectMcpServerValidationInput`
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
SDK/IDE protocol coverage still need direct Rust daemon-core ownership. The
Slice 785 MCP JS validation helper-retirement matrix-compaction pass is
complete. No matrix-compaction pass is pending until the next Rust-core
extraction or facade-retirement seam lands.
Slice 786 moved public memory manager status and validation projection into the
Rust daemon-core migration transport. `MemoryManagerStatusProjectionCore` and
`MemoryManagerValidationProjectionCore` now own canonical
`ioi.runtime_memory_manager_status` / `ioi.runtime_memory_manager_validation`
envelopes, while `memoryStatusForProjection()` and
`validateMemoryProjection()` remain only thin JS transport wrappers around
`contextPolicyRunner.planMemoryManagerStatusProjection()` /
`planMemoryManagerValidationProjection()`. Public memory status/validate routes
therefore no longer calculate readiness, issue counts, memory-key counts,
write-block reasons, routes, validation records, or evidence refs in JS. This
still does not claim terminal memory migration: direct Rust daemon-core memory
record truth, Agentgres admission/head/state-root binding, wallet authority,
StepModuleRouter dispatch for admitted memory work, cTEE custody coupling,
replay, SDK/IDE protocol coverage, and direct Rust API replacement for command
transport still need ownership. The Slice 786 memory manager projection
Rust-core matrix-compaction pass is complete. No matrix-compaction pass is
pending until the next Rust-core extraction or facade-retirement seam lands; do
not encode the command bridge or JS transport wrappers as terminal
architecture.
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
closed unless that Rust-authored receipt is present, and
`receipt-operations.mjs` now rejects generic JS model_mount receipt creation
with `model_mount_js_receipt_creation_retired`. JS may still persist the
Rust-authored receipt through the existing Agentgres receipt-state commit gate,
but it no longer synthesizes the accepted `model_route_selection` receipt. This
still does not claim terminal model_mount migration: direct Rust daemon-core
route-control/projection APIs, Agentgres route truth beyond the current commit
gate, wallet authority binding, StepModuleRouter dispatch, replay, and direct
Rust API replacement for command transport still need ownership. The Slice 791
route-selection receipt Rust-authoring matrix-compaction pass is complete. No
matrix-compaction pass is pending until the next Rust-core extraction or
facade-retirement seam lands; do not encode the command bridge or JS transport
wrappers as terminal architecture.
Slice 792 moved model_mount read-projection authoring out of the JS
`read-projection-facade.mjs` helper path and into Rust daemon-core projection
planning. `plan_model_mount_read_projection` now authors the canonical
model_mount projection, projection summary, route-decision projection, receipt
replay, and wallet authority snapshot envelopes through the Rust command
transport; the JS facade prepares current state input, calls
`planReadProjection()`, and fails closed with
`model_mount_read_projection_rust_core_required` when Rust projection planning
is unavailable. This still does not claim terminal model_mount migration:
current state materialization and command transport remain migration plumbing,
and direct Rust daemon-core APIs still need to own storage-backed projection
reads, Agentgres projection watermarks, replay, wallet authority binding,
SDK/IDE protocol coverage, and replacement of the bridge process boundary. The
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
no longer require broad snapshot/projection state materialization.
`projectionSummary()` and `modelRouteDecisions()` now send only admitted
receipts into `plan_model_mount_read_projection`; `authoritySnapshot()` sends
only server authority status, grants, vault refs, receipts, wallet status, and
vault status; `latestProviderHealth()` sends only provider records,
provider-health records, and receipts; and `latestVaultHealth()` sends only
receipts. The Rust `projection_summary` planner now authors its summary
directly from receipt truth instead of rebuilding the full projection object.
This still does not claim terminal model_mount projection migration: full
`projection`, `snapshot`, `receipt_replay`, runtime engine, and other broad
read surfaces still need direct Rust daemon-core Agentgres projection APIs to
replace remaining JS state materialization and command transport.

Slice 808 slimmed public model_mount receipt replay. `receiptReplay()` now sends
only admitted receipts plus route, endpoint, instance, and provider records into
`plan_model_mount_read_projection`; it no longer requires broad
snapshot/projection state input from the JS facade. The Rust `receipt_replay`
planner now builds a replay lookup context directly from that slim state instead
of rebuilding the full `model_mount` projection before locating the requested
receipt. This still does not claim terminal model_mount projection migration:
full `projection`, `snapshot`, runtime engine, and other broad read surfaces
still need direct Rust daemon-core Agentgres projection APIs to replace
remaining JS state materialization and command transport.

Slice 809 retired the snapshot helper's internal full-projection rebuild.
`snapshot()` still requests the Rust `snapshot` read-projection kind, but
`model_mount_snapshot()` no longer calls `model_mount_projection(request)` just
to recover adapter boundaries and projection summary. It now authors the nested
summary from receipt truth through `model_mount_projection_summary(request)` and
authors adapter boundaries directly through `model_mount_adapter_boundaries()`.
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
when no admitted survey receipt exists. This still does not claim terminal
runtime-survey migration: capture still fails closed until direct Rust
daemon-core survey APIs own hardware/runtime probing, Agentgres admission,
record-state, projection, and command-transport retirement.

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
planner. This still does not claim terminal runtime-survey migration: direct
Rust daemon-core runtime-survey APIs still need to replace JS hardware/runtime
probing, Agentgres admission, record-state, and command transport.

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
hosted/non-migrated providers. `modelMountProviderInvocationRequiresRust()` and
`modelMountProviderStreamInvocationRequiresRust()` now report that every
provider invocation path requires Rust `model_mount` ownership, while the
request builders fail closed with
`model_mount_provider_invocation_rust_backend_required` when a provider kind
does not yet have a Rust execution backend. This prevents hosted/OpenAI,
fixture-stream, or other unsupported provider paths from being represented as
JS-compatible escape hatches while the public invocation facades remain
fail-closed. This still does not claim terminal provider migration: direct Rust
daemon-core hosted/provider transports, provider request shaping, projection,
Agentgres-backed reads, and command-transport retirement remain required.

Slice 821 retired hosted/non-migrated provider-result observation admission
from the JS helper path. `modelMountProviderResultAdmissionRequestForExecution()`
now derives the expected Rust provider invocation backend from the selected
provider and stream status, rejects unsupported selections with
`model_mount_provider_result_rust_backend_required`, and rejects mismatched
`providerResult.execution_backend` before an `ioi.model_mount.provider_result.v1`
request can be assembled. Fixture/local-folder and native-local Rust-backed
outputs remain admissible; hosted/OpenAI output text can no longer be wrapped
as a Rust provider result by JS. This still does not claim terminal provider
migration: direct Rust daemon-core hosted/provider transports, provider request
shaping, projection, Agentgres-backed reads, and command-transport retirement
remain required.

Slice 822 moved the provider-result backend invariant into the Rust
`model_mount` core. `ModelMountProviderResultAdmissionRequest::validate()` no
longer accepts `js_provider_driver_observation`; provider-result admission now
requires one of the Rust-owned provider result backends
(`rust_model_mount_fixture`, `rust_model_mount_native_local`, or
`rust_model_mount_native_local_stream`) and binds the record with
`rust_model_mount_provider_result_backend_bound` evidence. The
`ioi-step-module-bridge` command path now proves fixture provider-result
admission through Rust and also proves the retired JS observation backend fails
closed with `UnsupportedProviderResultBackend`. This still does not claim
terminal provider migration: direct Rust daemon-core hosted/provider transports,
provider request shaping, projection, Agentgres-backed reads, and
command-transport retirement remain required.

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
non-OAuth auth-header vault-resolution helpers. `catalogProviderRuntimeMaterial()`
now preserves already-materialized session projections but fails closed with
`model_mount_catalog_provider_control_rust_core_required` for configured source
material before JS can resolve vault refs, parse catalog source material, or
project missing/failed vault material. `catalogProviderAuthHeaders()` now fails
closed with the same Rust catalog-provider control boundary for bearer/raw/API
key header material before JS can resolve vault refs, write vault metadata, or
shape plaintext auth headers. This still does not claim terminal
catalog-provider migration: direct Rust daemon-core catalog provider custody,
auth-header resolution, Agentgres-backed provider projection, local catalog
materialization retirement, and direct Rust APIs remain required before catalog
provider reads and auth can execute again.

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
mounted `catalogSearch()` facade now fails closed with
`model_catalog_search_js_orchestrator_retired` before JS can normalize search
filters, iterate catalog provider ports, enrich catalog entries, aggregate
provider results, or write `lastCatalogSearch`. Provider-level catalog search
paths were already retired in prior slices; this slice removes the remaining
JS search coordinator and leaves catalog search blocked until direct Rust
daemon-core catalog search/projection APIs own the request.

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
read-projection boundary. Public `catalogStatus()` now calls
`plan_model_mount_read_projection` kind `catalog_status` with empty request
state, translates only the Rust `model_catalog_status_js_readback_retired`
refusal at the JS edge, and no longer imports dead JS `catalogStatus()` or
`catalogStatusProjectionInput()` helpers. The Rust
bridge direct `catalog_status` arm fails closed even when a direct caller
provides `catalog_status_input`; broad `snapshot` and `projection` nested
`catalog` envelopes remain schema-stable empty/default objects instead of
honoring caller-supplied catalog-status input. This is still current-lane
bridge work, not the long-term resting architecture: direct Rust daemon-core
Agentgres-backed catalog status/projection APIs must replace command transport
and the remaining JS facade/error-translation edge before the catalog surface
reaches terminal unification.

Slice 868 retired the remaining runtime-survey projection-input and LM Studio
runtime placeholder helpers from JS. The runtime-daemon public `runtimeSurvey()`
facade still fails closed before hardware probes, runtime-engine reads, LM Studio
public-CLI execution, receipt creation, or projection writes. The latest
runtime-survey readback already uses Rust `latest_runtime_survey` receipt-only
projection, so `latestRuntimeSurveyProjectionInput()`,
`lmStudioRuntimeEngines()`, and `lmStudioRuntimeSurvey()` were deleted instead
of being preserved as non-authoritative compatibility shims. This is still not
terminal runtime-survey migration: direct Rust daemon-core runtime probing,
Agentgres-admitted survey truth, projection persistence, command-transport
retirement, and stable protocol APIs remain required before runtime survey
reaches the pure Rust substrate target.

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
provider records only, and `read-projection-facade.mjs` no longer injects
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
from the mounted model_mount facade. `catalogSearch()` already fails closed with
`model_catalog_search_js_orchestrator_retired`; the mounted facade stopped
injecting `catalogProviderStatus()` or `normalizeLimit()` into the retired search
operation. The public facade can
therefore no longer accidentally restore JS provider-status shaping, filter
normalization, provider iteration, entry enrichment, result aggregation, or
`lastCatalogSearch` writes through unused dependency hooks. Direct Rust
daemon-core catalog search/projection APIs still need to own the request before
catalog search reaches terminal substrate unification.

Slice 843 retired cached catalog-provider runtime-material readback from the JS
catalog-provider control surface. `catalogProviderRuntimeMaterial()` now fails
closed with `model_mount_catalog_provider_control_rust_core_required` even when
`catalogProviderRuntimeMaterials` already contains a bound, missing, or failed
runtime-material projection, so local JS cache entries can no longer stand in
for Rust daemon-core wallet/cTEE custody projection. Catalog-provider port
health helpers also no longer call `state.catalogProviderRuntimeMaterial()` for
local-manifest, Hugging Face-compatible, or custom HTTP catalog provider health;
they may report only env-gated metadata until direct Rust daemon-core catalog
provider projection owns admitted provider material. This keeps the current
bridge/facade path explicitly non-terminal and prevents context compaction from
encoding cached JS material as the long-term substrate shape.

Slice 844 retired private catalog-provider configuration readback and
config-derived auth-header projection from JS. The mounted
`catalogProviderConfig()` helper now fails closed at
`model_mount.catalog_provider_configuration.read_private`, and
`catalogProviderRuntimeMaterial()` no longer peeks into
`state.catalogProviderConfigs` for source-material hints. Catalog-provider
auth-header resolution now fails closed before calling
`state.catalogProviderConfig()` or deriving auth vault hashes, schemes,
header-name hashes, OAuth session hashes, or plaintext header shape from JS
config. Catalog-provider port health helpers also no longer call
`state.catalogProviderConfig()`; they may report only env-gated metadata until
direct Rust daemon-core catalog-provider projection owns admitted provider
configuration, custody, and auth-header readiness.

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
records. `deriveBackendRegistry()` no longer passes `state.providers` into
`backendRegistryRecords()`, and the default backend registry no longer reads
LM Studio, OpenAI-compatible, Ollama, or vLLM provider records to project backend
status, base URLs, or public-CLI binary paths. Backend records may still expose
env/binary-gated migration metadata, but provider-map records can no longer
become backend lifecycle/projection truth; direct Rust daemon-core backend and
provider projection APIs must own admitted backend/provider truth before the
terminal pure Rust substrate target is met.

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
`projection` requests. Dedicated runtime-engine read projections still use
narrow Rust-planned inputs, but local JS runtime-engine maps/preferences can no
longer become public projection truth through the broad Rust projection
envelope.

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
Dedicated `authority_snapshot` and `adapter_boundaries` read projections still
use narrow Rust-planned inputs, but local JS wallet/vault/Agentgres adapter
state can no longer become public authority or adapter-boundary truth through
the broad Rust projection envelope.

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
remains receipt-only. JS volatile server-control state can no longer become
public server truth through either the broad Rust projection envelope or the
dedicated server-status readback.

Slice 857 retired dedicated authority and adapter-boundary JS read-projection
input. The `adapter_boundaries` read projection now sends an empty state object
and Rust authors wallet, vault, OAuth, and Agentgres boundary metadata directly
instead of echoing JS `adapterStatus()` objects. The `authority_snapshot` read
projection now sends only admitted receipts instead of JS
`server_status_input`, grants, vault refs, wallet status, or vault status.
Direct Rust daemon-core wallet/vault/Agentgres authority projection still needs
to replace the remaining receipt-only/default authority envelope before
terminal authority projection is complete.

Slice 858 retired dedicated runtime-engine JS read-projection input. The
`runtime_engines`, `runtime_engine_profiles`, `runtime_preference`,
`runtime_preference_for_endpoint`, `runtime_default_load_options`, and
`runtime_engine_detail` read projections now send empty state objects from the
runtime-daemon facade. Rust returns empty list/profile projections, null
preference/default-load projections, and fails closed with
`model_mount_runtime_engine_not_found` for runtime-engine detail until direct
Rust daemon-core runtime-engine projection APIs own the surface. Direct Rust
runtime-engine projection, Agentgres-backed runtime-engine truth,
preference/profile/default-load ownership, command-transport replacement, and
local runtime-engine materialization retirement still remain before this
surface reaches the pure Rust substrate target.

Slice 859 retired dedicated latest-runtime-survey JS primitive read-projection
input. The `latest_runtime_survey` read projection now sends only admitted
receipts from the runtime-daemon facade and no longer imports
`latestRuntimeSurveyProjectionInput()`, reads JS runtime-engine preferences, or
passes JS hardware/probe fallback data. Rust ignores `runtime_survey_input` for
this projection: not-checked survey readback returns zero/null/default values,
and checked survey readback is derived only from admitted `runtime_survey`
receipt details. Direct Rust daemon-core runtime probing, Agentgres-admitted
survey capture, command-transport replacement, and local survey materialization
retirement still remain before this surface reaches the pure Rust substrate
target.

Slice 860 retired dedicated provider-health JS read-projection input. The
`provider_health` read projection now sends an empty state object and returns
the Rust default empty list; the Rust bridge `provider_health` arm also ignores
caller-supplied provider-health records so direct bridge callers cannot promote
local JS telemetry into projection truth. The `latest_provider_health` read
projection now sends only admitted receipts and no longer reads JS provider
records or local provider-health files. Rust derives the latest provider-health
envelope only from admitted `provider_health` receipt details with canonical
`provider_id`, and missing receipt truth fails closed with
`model_mount_provider_health_not_found`. Direct Rust daemon-core provider
health capture, Agentgres-admitted health writes, provider-control APIs,
command-transport replacement, and local provider-health materialization
retirement still remain before this surface reaches the pure Rust substrate
target.

Slice 861 retired dedicated model-topology list JS read-projection input. The
`artifacts`, `providers`, `endpoints`, `instances`, `routes`,
`model_capabilities`, and `downloads` read projections now send empty state
objects from the runtime-daemon facade, and the Rust bridge direct arms return
empty/default lists instead of echoing caller-supplied topology arrays. This
prevents local JS maps from becoming public topology or capability-list truth
through the dedicated list surfaces while direct Rust daemon-core Agentgres
topology projection APIs are still pending. Product artifact/catalog readbacks
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
model-capability, and ad hoc timestamp helper tree was deleted, and the focused
JS fixture planner mirrors the default envelope rather than reimplementing the
old derivation. Receipt replay remained a separate topology-lookup seam.

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
objects. Rust returns empty list/profile projections, null preference/default
load projections, and fails closed with `model_mount_runtime_engine_not_found`
for detail until direct Rust daemon-core Agentgres-backed runtime-engine
projection APIs own that truth. This keeps `ioi-step-module-bridge` as a
temporary command transport and prevents direct bridge callers from reintroducing
JS runtime-engine maps as projection truth.

Slice 866 moved public OAuth session/state readback refusal onto the Rust
read-projection boundary. Public `listOAuthSessions()` and `listOAuthStates()`
now call `plan_model_mount_read_projection` kinds `oauth_sessions` and
`oauth_states` with empty request state, translate only the Rust refusal at the
JS edge, and no longer import the dead `oauthSessionList()`/`oauthStateList()`
helpers. The Rust bridge direct arms for `oauth_sessions` and `oauth_states`
fail closed with `model_mount_oauth_read_projection_js_retired` even when direct
callers provide OAuth session/state arrays, and broad `snapshot`/`projection`
OAuth fields remain schema-stable empty arrays. Direct Rust daemon-core
wallet/cTEE OAuth projection APIs still need to replace this refusal before
OAuth public readback can be live.

Slice 867 moved public catalog-status readback refusal onto the Rust
read-projection boundary. Public `catalogStatus()` now calls
`plan_model_mount_read_projection` kind `catalog_status` with empty request
state, translates only the Rust `model_catalog_status_js_readback_retired`
refusal at the JS edge, and no longer imports JS catalog-status helper
scaffolding. Direct Rust catalog status/projection APIs, Agentgres-backed
catalog truth, command-transport replacement, edge error translation retirement,
and local catalog materialization retirement still remain before this surface
reaches the pure Rust substrate target.

Slice 868 retired the runtime-survey projection-input and LM Studio runtime
placeholder helpers from JS. Latest runtime-survey readback already uses Rust
`latest_runtime_survey` receipt-only projection, so
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
readback had moved to Rust receipt-only projection. The mounted public
`ModelMountingState.runtimeSurvey()` method now owns the edge refusal directly,
without importing a helper module or dependency-injecting JS probe helpers.
The method still fails closed before hardware probes, runtime-engine reads,
LM Studio public-CLI execution, receipt creation, or projection writes. This
does not claim terminal runtime-survey migration: direct Rust daemon-core
runtime probing, Agentgres-admitted survey truth, projection persistence,
command-transport retirement, and stable protocol APIs remain required.

Slice 871 retired the fail-closed `catalog-provider-oauth.mjs` helper module
after public catalog-provider OAuth start/callback/exchange/refresh/revoke had
already been reduced to Rust-core-required edge refusals. The mounted public
`ModelMountingState` OAuth methods now own provider configurability preflight,
callback `state` validation, and `model_mount.catalog_provider_oauth.*`
Rust-core-required errors directly, without importing a helper module or
injecting JS projection/custody helpers. This does not claim terminal OAuth
custody migration: direct Rust daemon-core wallet/cTEE OAuth state/session
projection APIs, Agentgres-admitted OAuth truth, command-transport retirement,
and edge error-envelope translation retirement still remain.

Slice 872 retired the fail-closed `storage-operations.mjs` helper module after
public download-cancel, artifact-delete, and storage-cleanup mutations had
already been reduced to Rust-core-required edge refusals. The mounted public
`ModelMountingState` storage methods now own canonical storage request alias
rejection, download-status not-found projection details, and
`model_mount.storage` Rust-core-required errors directly, without importing a
helper module or dependency-injecting destructive-confirmation, filesystem, or
hash helpers that cannot run before the Rust boundary. This does not claim
terminal model storage migration: direct Rust daemon-core
artifact/download/storage filesystem control, Agentgres-admitted receipt and
record-state truth, projection persistence, command-transport retirement, and
stable protocol APIs remain required.

Slice 873 retired the fail-closed `capability-token-operations.mjs` helper
module after public capability-token create/revoke and Bearer authorization had
already been reduced to Rust-core-required wallet-authority edge refusals. Slice
946 then retired the remaining public token-list JS projection: mounted
`ModelMountingState.listTokens()` now fails closed at
`model_mount.capability_token.list`, and the orphaned `publicToken()` redaction
helper is deleted rather than preserved as a compatibility formatter. Mounted
public capability-token methods still own canonical `token_id` not-found
details, Bearer authorization preflight, token-hash lookup, and
`model_mount.capability_token` Rust-core-required errors directly, without
importing a helper module or dependency-injecting wallet-authority helpers.
This does not claim terminal wallet authority migration: direct Rust
daemon-core wallet.network grant creation, revocation, authorization,
Agentgres-admitted receipt and record-state truth, projection persistence,
command-transport retirement, and stable protocol APIs remain required.

Slice 874 retired the fail-closed `vault-operations.mjs` helper module after
public vault bind/remove and vault-health receipt facades had already been
reduced to Rust-core-required wallet/cTEE custody edge refusals. Slice 947 then
retired the remaining public vault list/status/metadata JS readbacks:
`ModelMountingState.listVaultRefs()`, `vaultRefMetadata()`, and `vaultStatus()`
now fail closed at `model_mount.vault_ref.list`,
`model_mount.vault_ref.metadata`, and `model_mount.vault.status`, and the
orphaned `publicVaultRefs()` formatter is deleted. The mounted public
`ModelMountingState` vault methods still own canonical vault request alias
rejection, required `vault_ref`/`material` preflight, and `model_mount.vault`
Rust-core-required errors directly, without importing a helper module or
dependency-injecting wallet/cTEE custody helpers. This does not claim terminal
vault custody migration: direct Rust daemon-core wallet.network/cTEE vault
binding, removal, health receipts, Agentgres-admitted record-state truth,
projection persistence, command-transport retirement, and stable protocol APIs
remain required.

Slice 875 retired the fail-closed `tokenizer-operations.mjs` helper module after
public tokenize/count/context-fit utilities had already been reduced to
Rust-core-required model tokenizer edge refusals. The mounted public
`ModelMountingState` tokenizer/context-fit methods now own canonical tokenizer
request alias rejection, operation-specific `model_mount.tokenizer`
Rust-core-required errors, and context-window fallback reads directly, without
importing a helper module or dependency-injecting JS tokenization/truncation
helpers. This does not claim terminal tokenizer migration: direct Rust
daemon-core tokenizer/context-fit admission and projection, receipt/state-root
binding, Agentgres truth, replay, command-transport retirement, and stable
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

Slice 877 retired the fail-closed `catalog-download-operations.mjs` helper
module after public catalog-import URL and direct model-download mutations had
already been reduced to Rust-core-required catalog/download edge refusals. The
mounted public `ModelMountingState` catalog/download methods now own canonical
catalog import URL, download identity, download control, and download metadata
request alias rejection plus operation-specific `model_mount.catalog_download`
Rust-core-required errors directly, without importing a helper module or
dependency-injecting JS transfer, fixture materialization, filesystem,
artifact/download record-state, or receipt helpers. This does not claim terminal
catalog/download migration: direct Rust daemon-core catalog/download admission,
filesystem custody, receipt/state-root binding, Agentgres truth, replay,
command-transport retirement, and stable protocol APIs remain required.

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
truth, projection persistence, command-transport retirement, and stable
protocol APIs remain required. The current `ioi-step-module-bridge` command
path is migration scaffolding for proving a stable daemon-to-kernel protocol
surface, not a permanent bridge binary, and must not be treated as the terminal
substrate; the transport must collapse into the Rust daemon core API.

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
readback: conversation-state list projection now fails closed at
`model_conversation_state_list` until direct Rust daemon-core projection owns
that surface. This does not claim terminal conversation migration: direct Rust
daemon-core conversation admission/projection, receipt/state-root binding,
Agentgres truth, replay, command-transport
retirement, and stable protocol APIs remain required.

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
admission, projection, replay, command-transport retirement, and stable
protocol APIs remain required.

Slice 883 retired the fail-closed `model-loading-operations.mjs` helper module
after public load/unload mutation paths had already been reduced to
Rust-core-required instance lifecycle edge refusals. The mounted public
`ModelMountingState` model-loading methods now own canonical load request alias
rejection, endpoint/instance lookup, and `model_mount.instance_lifecycle`
Rust-core-required errors directly, without importing a model-loading helper or
preserving a standalone JS load/unload mutation surface. This does not claim
terminal instance lifecycle migration: direct Rust daemon-core load/unload
admission, provider lifecycle execution, receipt/state-root binding,
Agentgres truth, replay, projection, command-transport retirement, and stable
protocol APIs remain required.
Slice 930 retired the remaining JS estimate-only model-load projection path:
`ModelMountingState.loadEstimate()` and `estimateNativeLocalResources()` are
absent, and `load_options.estimate_only` now fails closed at
`model_mount.instance.estimate` with the same Rust daemon-core instance
lifecycle boundary before JS sizing, provider drivers, receipts, record-state
commits, or instance-map writes.
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
route-shaped compatibility wrapper after `load_options.estimate_only` was moved
to the Rust-core-required `model_mount.instance.estimate` boundary.
Slice 933 retired the load-option `estimateOnly` compatibility alias. The
load-option normalizer now honors only canonical `estimate_only`, and
`canonicalLoadOptionsInput()` strips `estimateOnly` before provider/runtime
normalization, so the retired public estimate path cannot be steered through a
camelCase request alias while canonical `estimate_only` still fails closed at
the Rust-core-required `model_mount.instance.estimate` boundary.
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
Slice 941 retired JS storage-summary filesystem scanning. Public
`ModelMountingState.storageSummary()` now fails closed at
`model_mount.storage.summary` with Rust-core-required evidence instead of
recursively listing model files, computing quota totals, or classifying
orphans from JS maps and local filesystem state. `catalog-helpers.mjs` no
longer exports `listModelFiles()`, `modelFileScore()`, or
`parseModelQuantization()`; the remaining file scoring and quantization parsing
are private to local artifact inspection only, so catalog/storage public truth
cannot re-enter through a reusable JS helper while Rust/Agentgres storage
projection is still pending.
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
`ModelMountingState.listBackends()` now fails closed at
`model_mount.backend.list` with
`model_mount_backend_projection_rust_core_required` instead of returning
`backendRegistry()` records derived from JS env, discovery, provider maps, or
process maps. The remaining backend registry state is migration plumbing for
backend process planning/default records only; terminal conformance still
requires direct Rust daemon-core backend projection over Agentgres-admitted
topology and lifecycle truth.
Slice 944 removed backend-registry snapshots from native fixture materialization.
The Rust-backed native fixture artifact and endpoint records no longer carry
`backendRegistry` arrays from `state.backendRegistry()`, and fixture seeding no
longer calls that JS registry read while creating the artifact/endpoint records.
The records remain deterministic migration fixtures only; backend inventory,
process state, and lifecycle projection must come from direct Rust daemon-core
model_mount projection over Agentgres-admitted truth.
Slice 945 retired model-mounting MCP server JS projection readback. Public
`ModelMountingState.listMcpServers()` now fails closed at
`model_mount.mcp_server.list` with
`model_mount_mcp_projection_rust_core_required`, `publicMcpServer()` was deleted
as an orphaned JS readback shaper, and the runtime MCP catalog no longer merges
`store.modelMounting.listMcpServers()` into workspace/agent MCP catalog
projection. Runtime MCP catalog status/list/search may still project
workspace/agent MCP records through Rust planner commands; model-mounting MCP
server projection remains pending until Rust daemon-core projection and
Agentgres-backed MCP registry truth own that surface directly.
Slice 946 retired public capability-token JS projection readback. Public
`ModelMountingState.listTokens()` now fails closed at
`model_mount.capability_token.list` with
`model_mount_capability_token_rust_core_required`, and the orphaned
`publicToken()` formatter is deleted so JS no longer redacts, sorts, or returns
wallet grant records as a public read projection. `/api/v1/tokens` remains a
mounted route only as a fail-closed protocol edge until Rust daemon-core
wallet.network authority owns capability-token projection over admitted truth.
Slice 947 retired public vault JS projection readback. Public
`ModelMountingState.listVaultRefs()`, `vaultRefMetadata()`, and `vaultStatus()`
now fail closed at `model_mount.vault_ref.list`,
`model_mount.vault_ref.metadata`, and `model_mount.vault.status` with
`model_mount_vault_rust_core_required`, and the orphaned `publicVaultRefs()`
formatter is deleted so JS no longer returns vault metadata/status as a public
read projection. `/api/v1/vault/refs`, `/api/v1/vault/refs/meta`, and
`/api/v1/vault/status` remain mounted routes only as fail-closed protocol edges
until Rust daemon-core wallet.network/cTEE custody projection owns admitted
vault truth.
Slice 948 retired model-mount conversation-state JS list readback. Public
`ModelMountingState.listConversations()` now fails closed at
`model_conversation_state_list` with
`model_mount_conversation_rust_core_required`, so JS no longer returns
`this.conversations` sorted by `created_at` as a model conversation projection.
Direct Rust daemon-core model conversation projection over Agentgres-admitted
truth remains required before terminal conformance.
Slice 949 retired runtime subagent public JS readback. Public
`RuntimeSubagentControl.listSubagents()`, `getSubagent()`, and
`getSubagentResult()` now fail closed at `subagent.list`, `subagent.get`, and
`subagent.result` with `runtime_subagent_control_rust_core_required`, so JS no
longer returns `store.subagents` or `store.getRun()` data as subagent
projection truth. Direct Rust daemon-core subagent projection over
Agentgres-admitted lifecycle truth remains required before terminal
conformance.
Slice 950 retired runtime task/job public JS readback. Public
`RuntimeTaskJobControl.listTasks()`, `getTask()`, `listJobs()`, and `getJob()`
now fail closed at `task.list`, `task.get`, `job.list`, and `job.get` with
`runtime_task_job_control_rust_core_required`, so JS no longer derives task/job
projection truth from `store.listRuns()`. Direct Rust daemon-core task/job
projection over Agentgres-admitted run/task/job truth remains required before
terminal conformance.
Slice 959 retired the daemon-store task/job route pass-through wrappers. The
public task/job create/list/get/cancel routes now call the fail-closed
`RuntimeTaskJobControl` surface directly, so JS no longer preserves
`createTask()`, `listTasks()`, `getTask()`, `cancelTask()`, `listJobs()`,
`getJob()`, or `cancelJob()` as daemon-store compatibility wrappers. This does
not claim terminal task/job admission/projection: direct Rust daemon-core route
admission, wallet lifecycle authority, StepModuleRouter dispatch, Agentgres
expected-head/state-root binding, receipt/event materialization, replay,
projection, command-transport retirement, and stable SDK/IDE/CLI protocol APIs
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
projection, command-transport retirement, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 961 retired the daemon-store route pass-through wrappers for workflow
edit apply, diagnostics repair decision execution, workspace snapshot list, and
workspace restore preview/apply. Those public thread routes now call the
mounted fail-closed workflow-edit, diagnostics-repair, and workspace-snapshot
surfaces directly, so JS no longer preserves `applyWorkflowEditProposal()`,
`executeDiagnosticsRepairDecision()`, `listWorkspaceSnapshots()`,
`previewWorkspaceSnapshotRestore()`, or `applyWorkspaceSnapshotRestore()` as
daemon-store compatibility wrappers. This does not claim terminal workflow,
diagnostics, or workspace-snapshot migration: direct Rust daemon-core route
admission, wallet/cTEE authority where applicable, Agentgres
expected-head/state-root binding, receipt/artifact materialization, replay,
projection, command-transport retirement, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 962 retired the daemon-store approval route pass-through wrappers. The
public approval request, decision, approve/reject shortcut, and revoke routes
now call the mounted fail-closed approval surface directly, so JS no longer
preserves `requestThreadApproval()`, `decideThreadApproval()`, or
`revokeThreadApproval()` as daemon-store compatibility wrappers. This does not
claim terminal approval authority migration: direct Rust daemon-core route
admission, wallet.network grant/lease issuance, Agentgres expected-head and
state-root binding, receipt/event materialization, replay, projection,
command-transport retirement, and stable SDK/IDE/CLI protocol APIs remain
required before terminal pure Rust substrate conformance.
Slice 963 retired the daemon-store context-policy route pass-through wrappers.
The public workflow-only context-budget, thread context-budget, thread
compaction-policy, thread compact, and run context-budget routes now call the
mounted fail-closed context-policy surface directly, so JS no longer preserves
`evaluateContextBudget()`, `evaluateCompactionPolicy()`, or `compactThread()`
as daemon-store compatibility wrappers. This does not claim terminal
context-policy migration: direct Rust daemon-core route admission, Agentgres
expected-head/state-root binding, policy receipt/event materialization, replay,
projection, command-transport retirement, and stable SDK/IDE/CLI protocol APIs
remain required before terminal pure Rust substrate conformance.
Slice 964 retired the daemon-store MCP route pass-through wrappers. Public MCP
catalog, validation, import/add/remove/enable/disable, invoke, and serve
routes plus thread-scoped MCP import/add/remove/enable/disable, search/fetch,
invoke, serve, status, and validation routes now call the mounted MCP catalog,
control, and serve surfaces directly. JS no longer preserves the route-facing
MCP store wrappers as compatibility authority. This does not claim terminal MCP
migration: direct Rust daemon-core MCP admission/projection, wallet.network
external-exit authority, Agentgres expected-head/state-root binding, MCP
receipt/event materialization, replay, command-transport retirement, and stable
SDK/IDE/CLI protocol APIs remain required before terminal pure Rust substrate
conformance.
Slice 965 retired the remaining route-facing daemon-store pass-through
wrappers for workflow-edit proposal admission and run-level coding-tool budget
recovery. The thread workflow-edit proposal route now calls the mounted
fail-closed workflow-edit surface directly, and the run coding-tool budget
recovery route now calls the mounted fail-closed budget-recovery surface
directly. JS no longer preserves `proposeWorkflowEdit()` or
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
Slice 967 moved the coding-tool budget recovery Rust-core-required admission
refusal into the Rust daemon-core policy bridge. `CodingToolBudgetRecoveryAdmissionRequiredCore`
now emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes
`plan_coding_tool_budget_recovery_admission_required`, and the runtime daemon
mounts that runner into the coding-tool budget recovery surface. JS still
translates the Rust-authored refusal at the HTTP edge, but no longer acts as
the canonical author for budget recovery admission-required control or
blocked-event projection refusal when the daemon-core command is configured.
This does not claim terminal coding-tool budget recovery migration: direct Rust
daemon-core retry admission/projection, wallet.network approval authority,
Agentgres expected-head/state-root binding, policy receipts, retry-event
materialization, run persistence, replay, command-transport retirement, and
stable SDK/IDE/CLI protocol APIs remain required before terminal pure Rust
substrate conformance.
Slice 968 moved the diagnostics repair Rust-core-required admission refusal
into the Rust daemon-core policy bridge. `DiagnosticsRepairAdmissionRequiredCore`
now emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes
`plan_diagnostics_repair_admission_required`, and the runtime daemon mounts
that runner into the diagnostics repair surface. JS still translates the
Rust-authored refusal at the HTTP edge, but no longer acts as the canonical
author for diagnostics repair decision execution, operator override, retry
creation, repair decision resolution, or repair event append refusal when the
daemon-core command is configured. This does not claim terminal diagnostics
repair migration: direct Rust daemon-core repair admission/projection,
wallet.network/operator authority, Agentgres expected-head/state-root binding,
repair/operator receipts, retry-run admission, event materialization, replay,
command-transport retirement, and stable SDK/IDE/CLI protocol APIs remain
required before terminal pure Rust substrate conformance.
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
Slice 970 moved public skill/hook registry projection refusal authoring into the
Rust daemon-core policy bridge. `SkillHookRegistryProjectionRequiredCore` now
emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes
`plan_skill_hook_registry_projection_required`, and the runtime daemon
skill/hook surface uses the mounted context-policy runner to get the
Rust-authored refusal. JS no longer constructs `/v1/skills`, `/v1/hooks`, or
skill-hook catalog projection truth from filesystem discovery at the public
surface. The doctor route degrades with the Rust-core-required details rather
than rediscovering registry truth. This does not claim terminal skill/hook
registry migration: direct Rust daemon-core projection over Agentgres-admitted
governance/catalog truth, wallet authority where applicable, receipt/state-root
binding, replay, command-transport retirement, and stable SDK/IDE/CLI protocol
APIs remain required before terminal pure Rust substrate conformance.
Slice 971 moved public repository workflow projection refusal authoring into the
Rust daemon-core policy bridge. `RepositoryWorkflowProjectionRequiredCore` now
emits the canonical fail-closed envelope and snake_case detail payload,
`ioi_step_module_bridge` exposes
`plan_repository_workflow_projection_required`, and the runtime daemon
repository surface uses the mounted context-policy runner to get the
Rust-authored refusal. JS no longer constructs public repository workflow
projection truth for `/v1/repositories`, `/v1/repository-context`,
`/v1/branch-policy`, `/v1/github-context`, `/v1/pr-attempts`,
`/v1/issue-context`, `/v1/review-gate`, or `/v1/github-pr-create-plan`.
This does not claim terminal repository workflow migration: direct Rust
daemon-core projection over Agentgres-admitted repository workflow truth,
wallet.network authority for external capability exits, receipt/state-root
binding, replay, command-transport retirement, and stable SDK/IDE/CLI protocol
APIs remain required before terminal pure Rust substrate conformance.
Slice 951 retired runtime conversation-artifact public JS readback. Public
`RuntimeConversationArtifactControl.listConversationArtifacts()`,
`getConversationArtifact()`, and `listConversationArtifactRevisions()` now fail
closed at `artifact.conversation.list`, `artifact.conversation.get`, and
`artifact.conversation.revision.list` with
`runtime_conversation_artifact_control_rust_core_required`, so JS no longer
returns `store.conversationArtifacts` data as conversation-artifact projection
truth. Direct Rust daemon-core artifact projection over Agentgres-admitted
ArtifactRef/PayloadRef truth remains required before terminal conformance.
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
Slice 954 retired the remaining runtime bridge thread-control JS dispatch path.
`RuntimeBridgeThreadTurnControl.controlRuntimeBridgeThread()` now fails closed
at `thread.runtime_bridge.control` with
`runtime_bridge_thread_rust_core_required`, so JS no longer calls
`runtimeBridge.controlThread()` or bridge availability checks as an accepted
thread-control path. Direct Rust daemon-core admission, wallet/cTEE/session
authority, Agentgres expected-head/state-root binding, replay, and projection
remain required before terminal runtime bridge thread/turn/control conformance.
Slice 955 retired the remaining MCP serve `tools/call` JS dispatch path.
`RuntimeMcpControl.handleSingleMcpServeJsonRpc()` now returns a JSON-RPC
`runtime_mcp_serve_tool_call_rust_core_required` error at
`mcp.serve.tools.call`, so JS no longer resolves thread agents or calls
`invokeThreadToolAsync()` as the served tool-call admission path. Direct Rust
daemon-core MCP serve admission, wallet authority, StepModuleRouter dispatch,
receipt/state-root binding, Agentgres truth, replay, projection, and stable
SDK/IDE/CLI protocol APIs remain required before terminal MCP serve
conformance.
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
command-transport retirement, and stable SDK/IDE/CLI protocol APIs remain
required before terminal thread-tool conformance.
Slice 957 retired the daemon-store thread-control route pass-through wrappers.
The public mode/model/thinking and workspace-trust acknowledgement routes now
call the fail-closed `RuntimeThreadControl` surface directly, so JS no longer
preserves `updateThreadMode()`, `updateThreadModel()`,
`updateThreadThinking()`, or `acknowledgeWorkspaceTrustWarning()` as duplicate
store-level compatibility wrappers. This does not claim terminal
thread-control or workspace-trust admission: direct Rust daemon-core route
admission, wallet/cTEE/model-route authority, Agentgres expected-head/state-root
binding, receipt/event materialization, replay, projection, command-transport
retirement, and stable SDK/IDE/CLI protocol APIs remain required before
terminal conformance.
Slice 958 retired the daemon-store subagent route pass-through wrappers. The
public subagent list/spawn/wait/input/cancel/resume/assign/result routes now
call the fail-closed `RuntimeSubagentControl` surface directly, so JS no longer
preserves `listSubagents()`, `spawnSubagent()`, `waitSubagent()`,
`sendSubagentInput()`, `cancelSubagent()`,
`propagateSubagentCancellation()`, `resumeSubagent()`, `assignSubagent()`,
`getSubagentResult()`, `getSubagent()`, `subagentProjection()`, or
`appendThreadSubagentControlEvent()` as daemon-store compatibility wrappers.
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
command-transport retirement, and stable protocol APIs remain required.

Slice 885 retired the fail-closed `catalog-operations.mjs` helper module after
public catalog search orchestration, catalog-status readback, and non-search
catalog variant enrichment had already been reduced to Rust-core-required or
Rust read-projection edge refusals. Mounted `ModelMountingState` methods now own
storage-summary readback, `model_catalog_search_js_orchestrator_retired`, and
`model_catalog_variant_enrichment_js_retired` directly, without importing a
standalone catalog operations helper. This does not claim terminal catalog
migration: direct Rust daemon-core catalog search/status/variant projection APIs
over Agentgres-backed state, command-transport retirement, and stable protocol
APIs remain required.

Slice 886 retired the direct JS model-route selector and explicit endpoint
resolver from `routes.mjs`. Mounted `ModelMountingState.selectRoute()` and
`endpointIdsForExplicitModel()` now fail closed at
`model_mount.route.select` and `model_mount.route.explicit_model_endpoints`
before route-map reads, endpoint/provider reads, endpoint mounting, JS policy
evaluation, or JS candidate scoring. The remaining route-selection helpers are
limited to Rust admission request assembly, Rust-authored receipt persistence,
and migration transport around `admit_model_mount_route_decision`; they are not
a terminal bridge architecture. This still does not claim terminal model_route
migration: direct Rust daemon-core route-control/projection APIs over
Agentgres-backed state, stable protocol APIs, replay, and command-transport
retirement remain required before model route control reaches the pure Rust
substrate target.

Slice 887 retired the mounted JS provider-driver factory. The
`provider-driver-factory.mjs` module and its concrete-driver routing test were
deleted, and `ModelMountingState.driverForProvider()` now fails closed with
`model_mount_provider_driver_factory_retired` before allocating fixture,
native-local, OpenAI-compatible, Ollama, LM Studio, vLLM, or llama.cpp JS driver
objects. Lower-level driver modules remain only as explicitly retired
edge-adapter tests or fail-closed transport stubs until direct Rust daemon-core
provider execution/control APIs replace them. This does not claim terminal
provider migration: direct Rust daemon-core provider transports, lifecycle,
inventory, projection, Agentgres-backed replay, stable protocol APIs, and
command-transport retirement remain required before provider execution reaches
the pure Rust substrate target.

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
catalog search and variant enrichment already fail closed at their Rust
daemon-core catalog search/projection boundaries; JS no longer retains a
standalone catalog entry materialization library for retired catalog surfaces to
re-enter.

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
narrow primitive migration input inside `read-projection-facade.mjs`. JS still
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
`retiredFixtureCatalogSearchResult()`. Public catalog search already fails
closed before JS provider iteration, so provider ports now retain only
health/gating metadata until direct Rust daemon-core catalog search/projection
APIs own external, local-manifest, fixture, and Ollama catalog search.

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
boundary helper surface from JS. `catalog-provider-config.mjs` now retains only
the configurable-provider preflight and shared Rust-core-required error used by
the mounted fail-closed facades; `catalog-provider-config.test.mjs`,
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
`plan_model_mount_read_projection` through `read-projection-facade.mjs` with
narrow Rust-planned request state. Direct Rust daemon-core runtime-engine
preference/profile/projection APIs, Agentgres-backed truth, receipt/state-root
binding, replay, stable protocol APIs, and command-transport retirement remain
required before runtime-engine control reaches terminal pure Rust conformance.

Slice 913 deleted the final local provider driver adapter module.
`provider-local-drivers.mjs` and `provider-local-drivers.test.mjs` are absent
rather than preserved as Rust-planning wrapper classes for native-local or
fixture health, inventory, lifecycle, direct invoke, or stream invoke. The
mounted `driverForProvider()` factory remains fail-closed, local provider
invocation and stream invocation continue through Rust `model_mount`
admission/execution paths, and provider health/inventory/load/unload public
facades remain mounted Rust-core-required boundaries until direct Rust
daemon-core provider control/projection APIs own those surfaces. Direct Rust
daemon-core provider transports, inventory, lifecycle control, Agentgres-backed
truth, replay, stable protocol APIs, and command-transport retirement remain
required before provider execution/control reaches terminal pure Rust
conformance.

Slice 914 deleted the orphan JS model-capability materializer.
`model-capability.mjs` and `model-capability.test.mjs` are absent instead of
preserved as a daemon-side fallback capability builder after public
`listModelCapabilities()` and broad model_mount projection reads moved through
Rust `plan_model_mount_read_projection`. The SDK still declares the canonical
snake_case protocol contract, but the daemon no longer carries a self-tested JS
implementation that can reconstruct route/provider/artifact readiness as public
truth. Direct Rust daemon-core model-capability projection over Agentgres-backed
topology, receipt/state-root binding, replay, stable protocol APIs, and
command-transport retirement remain required before capability projection
reaches terminal pure Rust conformance.

Slice 915 deleted the orphan JS model-instance lifecycle planning facades while
leaving the Rust bridge and receipt-binding guards in place.
`ModelMountingState.planModelMountInstanceLifecycle()` is absent, and
`model-instance-lifecycle.mjs` no longer exports
`planModelMountInstanceLifecycleForMigratedProvider()`,
`modelMountInstanceLifecycleRequiresRust()`, or
`modelMountInstanceLifecycleFields()`. Direct instance lifecycle planning still
belongs to Rust `model_mount` through `plan_model_mount_instance_lifecycle` and
`RustModelMountAdmissionRunner.planInstanceLifecycle()`, while JS may only
reject public load/unload/maintenance mutations or validate that already
admitted lifecycle receipts carry Rust-bound hashes/evidence before store
persistence. Direct Rust daemon-core load/unload/evict/supersede APIs,
Agentgres-backed topology and instance truth, replay, stable protocol APIs, and
command-transport retirement remain required before instance lifecycle reaches
terminal pure Rust conformance.

Slice 916 retired the remaining JS route-control record and route-selection
receipt builder facades. `routes.mjs` no longer exports `upsertRouteRecord()`,
`routeSelectionReceipt()`, `routeSelectionReceiptForState()`,
`modelMountRouteDecisionRequestForSelection()`, or
`persistModelRouteSelectionState()`. Public route upsert/test and mounted
route-selection methods still reject retired request aliases and then fail
closed at the Rust daemon-core route-control boundary, but JS no longer
normalizes route records, allocates route-selection receipt ids, constructs
`ModelMountRouteDecisionRequest` payloads, or persists accepted route-selection
receipts. Direct Rust daemon-core route control/selection APIs,
Agentgres-backed route truth, receipt/state-root binding, replay, stable
protocol APIs, and command-transport retirement remain required before route
control reaches terminal pure Rust conformance.

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
that uses it. Direct Rust daemon-core load/unload/evict/supersede APIs,
Agentgres-backed topology and instance truth, replay, stable protocol APIs, and
command-transport retirement remain required before instance lifecycle reaches
terminal pure Rust conformance.

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
terminal condition is still open. Sprint work should therefore prioritize the
remaining route-family extraction and facade-retirement slices that turn current
Rust bridge/admission primitives into the sole authoritative hot-path substrate.

Current sprint objective:

- route each remaining live daemon route family through Rust core ownership for
  authority, StepModuleRouter dispatch, receipt/state-root binding, Agentgres
  admission, projection, cTEE custody, and replay semantics;
- demote surviving JS/TS code to product/API/IDE/SDK adapter behavior only;
- delete or fail-close compatibility shims once the canonical Rust-owned path is
  verified by focused tests and the tiered conformance command;
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

The migration should optimize for future comprehensibility, not only immediate
feature velocity. Split-brain architecture often reappears when files become too
large, concepts are scattered, compatibility shims linger, or dirty worktrees
make it unclear what changed in which slice.

Use these rules for every implementation slice:

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

#### Clean-slice commits

Each implementation slice should end with:

```text
targeted tests/checks pass
git diff --check passes for touched files
git status is understandable
commit created for the slice
commit pushed after the slice is verified
```

Do not stack many unrelated changes in one dirty worktree. The migration will
cross JS, Rust, docs, IDE, Agentgres, wallet.network, cTEE, and workflow
projection surfaces; clean commits are part of the architecture because they
make rollback, review, and context recovery possible.

Recommended slice shape:

```text
one route family
or one ABI object
or one projection mapper
or one Rust runner
or one conformance gate
```

Avoid "mega-slices" that touch daemon routes, Rust IPC, IDE UI, docs, and tests
all at once unless they are strictly necessary for one verified end-to-end seam.

#### Alpha compatibility policy

This codebase is alpha and has no downstream users that require legacy API
stability. Do not preserve compatibility shims once the new canonical path is
verified.

Use shims only as short-lived migration scaffolds:

```text
introduce shim
  -> shadow/gated/live parity proves new path
  -> remove old path
  -> update source-of-truth docs
  -> commit and push the slice
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

#### Implementation slice template

Use this template for each slice in the migration:

```yaml
ImplementationSlice:
  objective: one clear runtime/conformance outcome
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
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
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

- `packages/runtime-daemon/src/runtime-api-bridge.mjs` as an injected-only edge that must stay non-authoritative until direct Rust daemon-core runtime-service APIs replace bridge transport
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

Current lane note: after Slice 1006, public runtime account, runtime-node, tool
catalog, agent, thread, run, agent-run lifecycle, run wait, run conversation,
thread usage, thread turns, thread turn detail, thread events, run usage, run
events, run replay, run trace/inspect, run computer-use trace/trajectory, run
scorecard, run artifact, top-level usage, authority-evidence, public memory
list/policy/path/status/validation, and public/thread-scoped
conversation-artifact route-facing projections are no
longer JS-authored public truth. The daemon edge now
translates `RuntimeToolCatalogProjectionRequiredCore` and
`RuntimeLifecycleProjectionRequiredCore` fail-closed records for catalog and
lifecycle surfaces, and the mounted thread-memory surface fails closed for
public memory projections before JS `AgentMemoryStore` readback; conversation
artifact routes call the mounted fail-closed artifact surface directly before
daemon-store pass-through wrappers or JS artifact-store readback; public agent
create, top-level thread create, agent status/delete, and agent-scoped run
create routes call the mounted agent/run lifecycle surface directly; public
runtime account/node/tool catalog routes call the mounted tool surface directly;
public repository workflow routes call the mounted repository surface directly;
public skill and hook catalog routes call the mounted skill-hook registry
surface directly; public model catalog and model-capability routes call the
mounted model-mount read-projection surface directly;
model-mount `server_status` read projection now sends empty request state plus
request-level `base_url` into Rust, and the deleted JS
`serverStatusProjectionInput()` helper can no longer materialize public server
truth from volatile server-control state;
model-mount backend-lifecycle, server-control, runtime-engine, tokenizer, and
route-control Rust-core-required planner records now live in dedicated Rust
`model_mount/required/{backend_lifecycle,server_control,runtime_engine,tokenizer,route_control}.rs`
owner modules behind the facade-only `model_mount/required.rs` and stable
`ModelMountCore` facade, and the required-record Rust tests now live beside
those child owners instead of accumulating in the broad model-mount kernel file
or in the required facade;
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
model-mount runtime-engine read-projection defaults and runtime-engine detail
fail-closed behavior now live in the dedicated Rust
`model_mount/read_projection/runtime.rs` module, with module-local Rust proof
that caller-supplied JS runtime-engine maps, profiles, preferences, and default
load options cannot become projection truth;
model-mount topology/product-catalog default read projections now live in the
dedicated Rust `model_mount/read_projection/topology.rs` module, with
module-local Rust proof that caller-supplied JS artifacts, providers,
endpoints, instances, routes, capabilities, downloads, backends,
provider-health rows, runtime catalog rows, and OpenAI-compatible model-list
rows cannot become projection truth;
model-mount direct catalog-status and OAuth session/state readback refusals now
live in dedicated Rust `model_mount/read_projection/catalog.rs` and
`model_mount/read_projection/oauth.rs` modules, with module-local Rust proof
that these public direct readback surfaces fail closed at their Rust owner
boundaries until direct catalog-provider and wallet/cTEE projection APIs own
Agentgres-backed truth;
model-mount read-projection shared helpers now live in the dedicated Rust
`model_mount/read_projection/common.rs` module, with module-local Rust proof
that schema/generation defaults, array/object extraction, and receipt-kind
filtering are owned outside the broad dispatcher;
public studio intent-frame routing now calls the intent resolver dependency
directly instead of a daemon-store route wrapper;
public doctor routing now calls the mounted doctor-report aggregate directly,
and the doctor aggregate reads mounted tool and skill-hook surfaces instead of
rediscovering public registry truth through daemon-store catalog wrappers;
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
model-mount read-projection command with empty JS request state instead of the
JS backend registry/readback facade, and Rust currently returns the
non-authoritative empty backend projection until direct Agentgres-backed backend
truth owns inventory; public backend health/start/stop/log lifecycle refusals
now request a Rust `model_mount.backend_lifecycle` required record through
the daemon-core command bridge and JS only translates that Rust-authored
failure envelope before JS backend registry lookup, derived backend projection,
local backend kind inference, receipt creation, or process control can run;
public model-mount server-control mutation/log/event refusals now request a
Rust `model_mount.server_control` required record through the daemon-core
command bridge and JS only translates that Rust-authored failure envelope
before server-control state writes, operation recording, local log projection,
or event/log append can run;
public runtime-engine preference/profile mutation refusals now request a Rust
`model_mount.runtime_engine` required record through the daemon-core command
bridge and JS only translates that Rust-authored failure envelope before
runtime preference/profile record writes, map mutation, projection writes, or
receipt creation can run;
public tokenizer/count/context-fit utility refusals now request a Rust
`model_mount.tokenizer` required record through the daemon-core command bridge
and JS only translates that Rust-authored failure envelope before JS
authorization, route selection, tokenization/context-fit receipt synthesis,
route-state mutation, truncation, or response-envelope shaping can run;
public route-control and route-selection refusal envelopes now request a Rust
`model_mount.route_control` required record through the daemon-core command
bridge and JS only translates that Rust-authored failure envelope before route
map reads, endpoint/provider reads, endpoint mounting, JS policy evaluation,
route-control receipt synthesis, route-record mutation, or duplicate
route-selection truth can run;
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
the mounted thread-turn surface now fails closed for non-runtime resume,
non-runtime turn creation, and diagnostics-blocked turn creation before JS agent
status mutation, run creation, or turn projection can become accepted truth;
public usage, public authority-evidence, and `/api/v1` authority-evidence /
workflow-capability preflight routes call the mounted run-read surface directly;
and reload no longer reads JS agent state before fail-closed admission;
agent/thread memory write, edit, delete, policy, status, and validation routes
also call the mounted thread-memory surface directly before daemon-store
pass-through wrappers; thread fork,
managed-session inspection/control, workspace-change inspection, and run cancel
routes call a mounted auxiliary fail-closed surface instead of daemon-store
pass-through wrappers while direct Rust daemon-core projection and admission APIs
are extracted; thread resume, turn create, interrupt, and steer routes now call
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
admission, memory admission/projection, managed-session/workspace-change control,
thread-fork/run-cancel admission, runtime thread/turn control, and
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

Slice 1035 moves the policy projection-required refusal owner family for
skill/hook registry, repository workflow, runtime tool catalog, and runtime
lifecycle projections out of the broad Rust `policy.rs` facade into
`crates/services/src/agentic/runtime/kernel/policy/projection_required.rs`.
The facade now re-exports the child owner while conformance requires the child
module to retain the request/record/error types, planner cores, validation, and
focused proof tests. This is a directionally pure-Rust extraction cut: the
current JS context-policy runner and Node command bridge are still migration
transport, not canonical architecture. Resume by replacing those transport
paths with direct Rust daemon-core projection/admission APIs over
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
The child module owns budget-recovery state-update and admission-required
request/record/error types, planner cores, validation, helper operator-control
planning, and focused proof tests; the parent facade only re-exports the
surface. This is an extraction toward the pure Rust daemon-core substrate, not
the terminal budget recovery architecture. The current JS coding-tool budget
recovery facade, JS context-policy runner, and Node command bridge remain
temporary migration transport. Resume by replacing that transport path with
direct Rust daemon-core budget recovery admission/persistence over wallet
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

Slice 1049 moves the skill/hook registry, repository workflow, runtime tool
catalog, and runtime lifecycle projection-required daemon-core command wrappers
out of the monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs`
migration transport into
`crates/node/src/bin/ioi_step_module_bridge/projection_command.rs`. The
projection-required policy owner remains
`crates/services/src/agentic/runtime/kernel/policy/projection_required.rs`; the
bridge child module is only fixed migration transport that translates
Rust-authored projection-required refusal records at the process boundary. The
conformance guard now proves the projection-required command wrappers stay out
of the broad bridge module. This is not terminal projection migration. Resume
by replacing this command transport with direct Rust daemon-core projection
APIs for registry, repository workflow, tool catalog, lifecycle/run-read,
doctor/readiness, replay, and stable IDE/CLI/SDK surfaces over
Agentgres-admitted truth, receipt/state-root binding, wallet authority where
applicable, and cTEE custody where private workspace projection is involved.

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
not terminal cTEE, worker/service package, L1 settlement, or meta-improvement
migration. Resume by replacing this command transport with direct Rust
daemon-core APIs for custody, package invocation, settlement trigger guards,
governed proposal admission, receipt/state-root binding, Agentgres admission,
replay, projection, and stable IDE/CLI/SDK protocol surfaces.

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
invocation receipt binding, and read-projection command wrappers. The Rust
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

Slice 1056 moves the lower-level coding-tool workspace filesystem, path,
diagnostic subprocess, test-run, and patch helper plumbing out of the
monolithic Rust `crates/node/src/bin/ioi_step_module_bridge/mod.rs` migration
transport into
`crates/node/src/bin/ioi_step_module_bridge/coding_tool_helpers.rs`. The broad
bridge root now retains proof tests and child-module wiring, while the
coding-tool command transport imports helper plumbing from a dedicated Rust
sibling module and Slice 1057 moves temporary operation dispatch to
`bridge_dispatch.rs`.
Conformance now fails if the helper function bodies return to the root bridge.
This is still not terminal coding-tool migration and must not canonize the
Node bridge shape. Resume by moving this helper plumbing behind direct Rust
daemon-core coding-tool execution/admission APIs and Rust/WASM workload modules,
then retiring the command transport, JS invocation facade, readback shims,
duplicate truth paths, and any compatibility wrappers that survive the verified
Rust-core boundary.

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

Slice 1060 extends the same temporary helper to runtime Agentgres admission and
workspace restore. `runtime-agentgres-admission-runner.mjs` and
`runtime-workspace-restore-runner.mjs` now delegate fixed empty-argv command
spawn, mock handling, JSON parsing, process failure mapping, and Rust rejection
mapping to `runtime-daemon-core-command-runner.mjs` instead of importing
`node:child_process` directly. This reduces duplicated JS command transport on
the Agentgres truth path and restore planning/execution path, but it remains
migration scaffolding. Resume by collapsing the remaining large context-policy,
model-mount admission, and StepModule command surfaces where helpful, then
replace the shared helper and Node command bridge with direct Rust daemon-core
protocol/API ownership.

Slice 1061 extends the temporary helper to the remaining large daemon-core
command runners: context policy and model-mount admission.
`runtime-context-policy-runner.mjs` and
`model-mounting/model-mount-admission-runner.mjs` now delegate fixed empty-argv
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
IDE/CLI/SDK protocol surfaces.

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

Slice 1081 retires RuntimeAgentService bridge command/input alias tolerance at
both migration edges. The JS command adapter now rejects retired operation
payload aliases such as `threadId`, `sessionId`, `managedSessionId`,
`streamEventsOnly`, `requestHash`, and `workspaceChangeId` before spawning the
bridge command. The Rust `ioi-runtime-bridge` binary now deserializes only the
canonical `schema_version`, `bridge_id`, `thread_id`, `session_id`,
`runtime_profile`, `workspace_root`, `streamed_events_only`,
`managed_sessions_only`, `request_hash`, `managed_session_id`, and `change_id`
fields.

Conformance now fails if the RuntimeAgentService adapter stops rejecting
retired input aliases or if the Rust bridge binary regains serde alias
tolerance for those bridge command/input fields. This still does not make the
RuntimeAgentService bridge terminal architecture: it remains fixed migration
transport until direct Rust daemon-core runtime thread/turn/control APIs own
admission, execution dispatch, persistence, replay, projection, wallet/cTEE
policy, and Agentgres expected-head/state-root binding.

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

Slice 1083 moves the public operator turn-control admission-required refusal
contract into the Rust policy core. The Rust
`OperatorTurnControlAdmissionRequiredCore` now owns the canonical
`runtime_operator_turn_control_rust_core_required` record and the daemon-core
command protocol exposes it as
`plan_operator_turn_control_admission_required`. The JS
`RuntimeThreadTurn` surface mounts the context-policy runner and consumes this
Rust-authored record for interrupt/steer refusals, while still failing closed
before event append, runtime bridge control, run mutation, or JS state-update
planning.

Conformance now fails if the operator turn-control required-boundary envelope
is authored only in JS, if the new daemon-core command operation is removed
from Rust typed command dispatch, if public interrupt/steer calls invoke the
older Rust state-update planner directly, or if camelCase detail aliases return
on the refusal details. This remains non-terminal: direct Rust daemon-core
operator control admission, runtime control, Agentgres expected-head/state-root
commit, replay, and projection must still replace the temporary command
transport.

Slice 1084 moves the public non-runtime thread-turn admission-required refusal
contract into the Rust thread-lifecycle policy core. The Rust
`ThreadTurnAdmissionRequiredCore` now owns the canonical
`runtime_thread_turn_rust_core_required` record and the daemon-core command
protocol exposes it as `plan_thread_turn_admission_required`. The JS
`RuntimeThreadTurn` surface consumes this Rust-authored record for non-runtime
resume, non-runtime turn creation, and diagnostics-blocked turn creation while
still failing closed before JS `updateAgent()`, `createRun()`, `turnForRun()`,
runtime-event append, run/agent persistence, or Agentgres commit.

Conformance now fails if the thread-turn required-boundary envelope is authored
only in JS, if the new daemon-core command operation is removed from Rust typed
command dispatch, if the temporary Node command wrapper drifts back into the
broad bridge module, or if the public surface stops proving it called the Rust
admission-required planner before any JS mutation path. This remains
non-terminal: direct Rust daemon-core thread-turn admission, runtime dispatch,
Agentgres expected-head/state-root commit, replay, projection, and stable
protocol APIs must still replace the temporary command transport.

Slice 1085 moves the public agent/run lifecycle admission-required refusal
family into the Rust thread-lifecycle policy core. The Rust
`LifecycleAdmissionRequiredCore` now owns the canonical required-boundary
records for agent creation, run creation, agent status control, and permanent
agent deletion, and the daemon-core command protocol exposes them through
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

Slice 1086 retires the `RuntimeDaemonStore.createAgent()`,
`RuntimeDaemonStore.createRun()`, and `RuntimeDaemonStore.createThread()`
compatibility pass-throughs. Public agent creation, top-level thread creation,
and agent-scoped run creation already enter through the mounted
`agentRunLifecycleSurface`; the daemon store no longer exposes a second
lifecycle creation method family that can be mistaken for the canonical
authority boundary after context compaction. Internal runtime-service fixtures
and proofs that still need the temporary mounted surface call it explicitly.

Conformance now fails if the daemon store re-imports the retired
`createAgentState`/`createRunState` helpers, reintroduces store-level
`createAgent()`/`createRun()`/`createThread()` wrappers, or routes public
agent/thread/run creation through the store compatibility layer instead of the
mounted lifecycle surface. This remains non-terminal: the mounted JS surface is
still migration scaffolding, and the next Rust-core cut must replace it with
direct Rust daemon-core lifecycle admission, persistence, replay, projection,
Agentgres expected-head/state-root binding, and stable protocol APIs.

Slice 1087 converts the stale `runtime-thread-control.test.mjs` live
runtime-service proof into negative boundary evidence. That test no longer
tries to seed model routes through retired JS model-mount mutation facades,
start runtime-service threads through JS bridge dispatch, or exercise subagent
recovery through removed daemon-store compatibility wrappers. Instead it proves
that route seeding fails through the Rust model-mount route-control required
record, runtime-service thread creation fails before JS runtime bridge
`startThread` dispatch or agent/run cache mutation, and the retired daemon-store
lifecycle and thread-control/subagent wrappers remain absent.

Conformance now fails if this test drifts back into a live JS runtime-service
proof or if it stops checking the Rust-required route-control and runtime
bridge boundaries. This remains non-terminal: runtime-service thread start,
turn submit, managed-session control, and subagent recovery still need direct
Rust daemon-core admission, dispatch, Agentgres binding, replay, and projection
before they can become active live proofs again.

Slice 1088 deletes the obsolete Stage 5 stop/cancel/recover and Stage 7
delegation live-GUI proof scripts that still encoded JS model-mount
`importModel`/`mountEndpoint` setup plus JS runtime-service bridge dispatch as
successful product proof. Those scripts were self-contained, unreferenced by
the conformance suite, and contradicted the current Rust-required boundary
where model-route mutation, runtime-service thread start, turn submit/control,
managed-session control, and subagent recovery must fail closed until direct
Rust daemon-core admission and Agentgres binding exist.

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

Slice 1092 retires the JS RuntimeAgentService command adapter itself. The
daemon no longer imports or exports `runtime-agent-service-adapter.mjs`, the
adapter module and positive command-spawn tests are deleted, and
`RuntimeApiBridge` no longer auto-configures command transport from
`IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND` or `IOI_RUNTIME_BRIDGE_COMMAND`.
The API bridge is now injected-only and unavailable by default, so runtime
service profiles cannot regain live execution through env-selected Node command
transport.

Conformance now fails if the retired adapter module/test return, if
`RuntimeApiBridge` re-imports the adapter factory, or if env bridge command
selection becomes a default runtime-service path again. The remaining
`ioi-runtime-bridge` Rust binary evidence is historical alias-rejection guard
coverage only; new positive runtime-service execution must land as direct Rust
daemon-core admission, Agentgres expected-head/state-root binding, replay, and
projection over stable protocol APIs.

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

Slice 1094 retires the standalone runtime bridge thread/turn/control JS facade
module instead of preserving it as a fail-closed compatibility wrapper.
`packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs` and its focused
test are deleted, and the daemon store no longer imports or exposes
`createRuntimeBridgeThread()` or `createRuntimeBridgeTurn()` pass-through
methods. Runtime-service thread start still fails closed at the agent lifecycle
surface, and runtime-service turn submit/control still fail closed at the
thread-turn surface before bridge dispatch, JS event append, in-flight
registration, agent/run map mutation, or persistence.

Conformance now treats the deleted module as the invariant. Future positive
runtime-service start, turn submit, and control must arrive through direct Rust
daemon-core admission, execution dispatch, Agentgres expected-head/state-root
binding, replay, and projection rather than by recreating a Node bridge-thread
facade.

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
approval surface or daemon store. The remaining approval-request event readback
is explicitly limited to the current coding-tool approval-satisfaction helper
until that helper receives a direct Rust daemon-core replacement.

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
surfaces remain migration scaffolding only: future direct positive APIs must be
owned by Rust daemon-core diagnostics repair admission/projection and
conversation-artifact admission/projection, with Agentgres expected-head and
state-root binding, receipt_binder, ArtifactRef/PayloadRef admission, replay,
and projection replacing the temporary protocol-edge surface calls.

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

Slice 1102 retires the daemon-store workspace-trust warning pass-through
delegate. The mounted thread-control surface still exposes
`appendWorkspaceTrustWarningEvent()` as a fail-closed migration surface, but
the daemon store no longer provides a duplicate `store.appendWorkspaceTrustWarningEvent()`
compatibility entrypoint, and conformance fails if that wrapper returns.

Workspace-trust warning and acknowledgement positive ownership remains a Rust
daemon-core target: direct Rust APIs must own wallet/cTEE workspace authority,
Agentgres expected-head/state-root binding, receipt/event materialization,
replay, and projection before the mounted protocol-edge surface can be retired.

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

Slice 1104 splits the Rust model_mount accepted-receipt planning and invocation
receipt binding command boundary out of
`ioi_step_module_bridge/model_mount_command.rs` into
`ioi_step_module_bridge/model_mount_receipt_command.rs`. The general
model_mount command wrapper no longer owns `ReceiptBinder`,
`AgentgresAdmissionCore`, or `RustProjectionCore` imports, while the new receipt
boundary owns accepted-receipt head/transition planning, caller-supplied expected
head rejection, transition validation, StepModuleRouter admission, receipt
binding, accepted-receipt append, Agentgres admission, and projection binding.

This is still temporary command-transport scaffolding, not the terminal direct
daemon-core API. It exists only to keep receipt/state-root ownership explicit
until direct Rust daemon-core model_mount protocol APIs replace the Node command
bridge and remaining JS model_mount facades.

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

Slice 1117 moves model_mount accepted-receipt response shaping and invocation
receipt binding/admission out of the temporary Node receipt bridge and into
Rust `model_mount_receipt.rs` under the kernel service crate. Rust core now
owns accepted-receipt head/transition command responses, model_mount
StepModule invocation/result gate checks, caller-supplied expected-head
rejection, Rust-planned accepted-receipt transition validation, transition
mismatch fail-closed checks, StepModuleRouter admission, receipt binding,
accepted-receipt append through `ReceiptBinder`, optional Agentgres operation
admission, projection record creation, and the canonical
`rust_model_mount_receipt_binding_command` response envelope.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, model-mount admission
runner, and model-mount JS protocol facades still exist. The remaining
`ioi_step_module_bridge/model_mount_receipt_command.rs` file is a temporary
delegate to Rust core, not a durable receipt/admission boundary. The long-term
target remains direct Rust daemon-core model_mount protocol APIs over
Agentgres-backed receipt/state-root binding, replay, projection, wallet.network
authority, cTEE custody where applicable, and stable IDE/CLI/SDK surfaces end
to end.

Slice 1118 moves governed receipt command response shaping for cTEE private
workspace execution and worker/service package invocation out of the temporary
Node receipt bridge and into Rust `governed_receipt.rs` under the kernel
service crate. Rust core now owns the governed receipt bridge request structs,
cTEE StepModule kind/backend guard, caller-supplied expected-head rejection,
private-workspace cTEE execution/admission wrapping, worker/service package
invocation admission wrapping, accepted-receipt append through `ReceiptBinder`,
and the canonical `rust_ctee_private_workspace_command` and
`rust_worker_service_package_invocation_command` response envelopes.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, cTEE runner, and
worker/service package runner still exist. The remaining
`ioi_step_module_bridge/governed_receipt_command.rs` file is a temporary
delegate to Rust core, not a durable receipt/admission boundary. The long-term
target remains direct Rust daemon-core cTEE and worker/service package protocol
APIs over Agentgres-backed receipt/state-root binding, replay, projection,
wallet.network authority, cTEE custody, and stable IDE/CLI/SDK surfaces end to
end.

Slice 1119 moves Agentgres storage-write admission and runtime-state commit
command response shaping out of the temporary Node Agentgres command bridge and
into Rust `agentgres_command.rs` under the kernel service crate. Rust core now
owns the Agentgres command bridge request structs, storage-write admission
response envelope, runtime run-state persisted commit response envelope,
agent/memory/subagent/artifact/model-mount record/model-mount receipt state
commit response envelopes, and the per-record persistence helper that writes
through `AgentgresAdmissionCore` after storage admission.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, runtime Agentgres
runner, and JS persistence callers still exist. The remaining
`ioi_step_module_bridge/agentgres_command.rs` file is a temporary delegate to
Rust core, not a durable Agentgres command boundary. The long-term target
remains direct Rust daemon-core Agentgres protocol APIs over admitted
receipt/state-root truth, replay, projection, wallet.network authority where
applicable, cTEE custody where applicable, and stable IDE/CLI/SDK surfaces end
to end.

Slice 1120 moves L1 settlement and governed runtime-improvement command
response shaping out of the temporary Node governed-admission command bridge
and into Rust `governed_admission.rs` under the kernel service crate. Rust core
now owns the governed admission bridge request structs, L1 trigger-guard
wrapping, governed-evolution proposal admission wrapping, canonical
`rust_l1_settlement_guard_command` and
`rust_governed_meta_improvement_command` response envelopes, and the error
codes returned to the bridge boundary.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command callers, L1 settlement runner,
and governed-improvement runner still exist. The remaining
`ioi_step_module_bridge/governed_admission_command.rs` file is a temporary
delegate to Rust core, not a durable governed-admission boundary. The long-term
target remains direct Rust daemon-core governed-admission protocol APIs over
settlement trigger guards, governed proposal admission, Agentgres-backed
receipt/state-root truth where applicable, replay, projection, wallet.network
authority where applicable, and stable IDE/CLI/SDK surfaces end to end.

Slice 1121 moves external capability exit authority command response shaping
out of the temporary Node authority command bridge and into Rust `authority.rs`
under the kernel service crate. Rust core now owns the bridge request struct,
wallet.network authority wrapping, canonical
`rust_external_capability_exit_authority_command` response envelope, authority
grant/receipt/hash projection fields, and bridge-facing error code for rejected
external exits.

This remains non-terminal because the Node bridge, command dispatch table,
shared daemon-core command runner, JS command caller, and external capability
authority runner still exist. The remaining
`ioi_step_module_bridge/authority_command.rs` file is a temporary delegate to
Rust core, not a durable wallet.network authority boundary. The long-term
target remains direct Rust daemon-core authority protocol APIs over
wallet.network grants, authority receipts, Agentgres-backed receipt/state-root
truth where applicable, replay, projection, and stable IDE/CLI/SDK surfaces end
to end.

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
