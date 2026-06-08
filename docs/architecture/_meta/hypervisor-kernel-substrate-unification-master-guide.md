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
| Command bridge | `packages/runtime-daemon/src/runtime-agent-service-adapter.mjs` can call an external command bridge for runtime agent service operations. | There is a product-level bridge mechanism that can evolve into a workload-client bridge. |

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
the Node/JS facade while Rust ownership is being proven route by route. It must
not be treated as the terminal substrate. After parity is proven, the bridge
surface should either collapse into the Rust daemon core API or be renamed and
shrunk into a narrow daemon/kernel protocol transport with no independent
execution authority, no compatibility-shim semantics, and no duplicate truth
path. The target transport shape is a temporary transport to the Rust daemon core
with no independent authority or compatibility-shim behavior.

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
755 workflow-edit read-helper facade-retirement compaction is complete.
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
IOI_STEP_MODULE_BACKEND=daemon_js|rust_workload_shadow|rust_workload_gated|rust_workload_live
IOI_WORKLOAD_GRPC_ADDR=...
IOI_SHMEM_ID=...
```

Likely files/modules:

- `packages/runtime-daemon/src/runtime-agent-service-adapter.mjs`
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
