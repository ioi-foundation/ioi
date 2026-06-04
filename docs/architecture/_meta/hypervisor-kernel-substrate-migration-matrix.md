# Hypervisor Kernel Substrate Migration Matrix

Status: implementation migration matrix.
Canonical owner: this file tracks live/current/final ownership for the Hypervisor kernel substrate unification migration; doctrine remains owned by the subject docs and the master guide.
Supersedes: ad hoc split-brain status notes for this migration when they conflict with the route-family owner map below.
Superseded by: none.
Last alignment pass: 2026-06-04.

## Purpose

This matrix is the Phase 0 inventory for
[`hypervisor-kernel-substrate-unification-master-guide.md`](./hypervisor-kernel-substrate-unification-master-guide.md).
It keeps each route family honest about current live authority, target owner,
truth path, conformance tier, and cleanup condition.

Terminal status is not claimed here. The migration is open until
`hypervisor-conformance` passes and the terminal conditions in the master guide
are all true.

## Implementation Slice 0

```yaml
ImplementationSlice:
  objective: restore the canonical guide, record the live-vs-target inventory,
    and wire the fail-closed conformance command contract
  owner_boundary:
    route_or_surface: migration/conformance surface
    authority_gate: Hypervisor Daemon plus wallet.network, not bypassed by this slice
    execution_backend: not changed; JS remains current live path until Phase 1+
    truth_path: documentation inventory only; no accepted runtime transition
    projection_path: conformance reporting only
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/source-of-truth-map.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon: []
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
      - package.json
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - npm run hypervisor-conformance:docs
      - node scripts/conformance/hypervisor-conformance.mjs abi
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS daemon execution paths remain current live implementation until the
        Step/Module ABI, bridge, receipts, and Rust core phases prove parity
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 1

```yaml
ImplementationSlice:
  objective: implement the shared StepModuleInvocation and StepModuleResult ABI
    in Rust and expose JS projection wrappers for every current coding tool
  owner_boundary:
    route_or_surface: coding tool ABI projection
    authority_gate: represented in invocation authority fields; no new gate owner
      introduced in this slice
    execution_backend: existing daemon_js execution represented as migration-only
      projection, not promoted as terminal authority
    truth_path: no accepted Agentgres mutation; ABI result enforces state binding
      when operation refs are present
    projection_path: StepModuleResult.workflow_projection in projection mode
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/step-module-abi.mjs
      - packages/runtime-daemon/src/coding-tools.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/step_module.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/step-module-abi.test.mjs
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/step_module.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services step_module
      - node --test packages/runtime-daemon/src/step-module-abi.test.mjs
      - npm run hypervisor-conformance:abi
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - daemon_js remains a migration-only Step/Module backend until the bridge
        and first routed tool slices prove parity
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 2

```yaml
ImplementationSlice:
  objective: add the daemon StepModuleRunner boundary, fail-closed Rust workload
    runner selection, and shadow/mock bridge projection for current coding tools
  owner_boundary:
    route_or_surface: coding tool runner boundary
    authority_gate: existing daemon approval/budget gates still run before any
      StepModuleRunner projection; gated/live Rust workload mode blocks before
      daemon_js execution until promoted
    execution_backend: daemon_js projection by default; rust_workload_shadow can
      call a command bridge or mock without becoming accepted truth
    truth_path: no Agentgres operation admission in this slice
    projection_path: coding-tool runtime events include step_module projection
      metadata and shadow runner errors
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/step-module-runner.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/step-module-runner.test.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - node --test packages/runtime-daemon/src/step-module-runner.test.mjs
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - daemon_js remains default until the first shadowed Rust/WASM tool and
        receipt/state-root slices prove parity
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 3

```yaml
ImplementationSlice:
  objective: shadow-route the first deterministic daemon tool, workspace.status,
    through a Rust StepModule command bridge
  owner_boundary:
    route_or_surface: workspace.status shadow bridge
    authority_gate: existing daemon budget/approval gates still run first
    execution_backend: rust_workload_shadow command bridge for projection; no
      live Rust workload promotion yet
    truth_path: no accepted Agentgres mutation in this slice
    projection_path: Rust StepModuleResult.workflow_projection with shadow status
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/step-module-runner.mjs
    rust_core:
      - crates/node/src/bin/ioi-step-module-bridge.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node runner smoke using IOI_STEP_MODULE_COMMAND=cargo and
        IOI_STEP_MODULE_COMMAND_ARGS='run -q -p ioi-node --bin ioi-step-module-bridge'
      - npm run hypervisor-conformance:bridge
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - workspace.status still executes daemon_js as the live path until receipt
        and projection parity gates promote Rust execution
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 4

```yaml
ImplementationSlice:
  objective: introduce the Rust StepModule receipt binder and include its
    binding in the workspace.status Rust shadow bridge response
  owner_boundary:
    route_or_surface: StepModuleResult receipt/ref/state-root binding primitive
    authority_gate: unchanged; existing daemon gates still precede the bridge
    execution_backend: Rust command bridge shadow path
    truth_path: receipt binding exists; Agentgres admission is still not promoted
      as live accepted truth in this slice
    projection_path: unchanged shadow StepModuleResult.workflow_projection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/receipt_binder.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi-step-module-bridge.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/receipt_binder.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services receipt_binder
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:receipts
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS receipt/event emission remains live until Agentgres admission and
        facade-retirement slices migrate accepted truth paths
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Route-Family Owner Map

| Route family | Current live anchor | Current owner | Final owner | Truth path target | Conformance tier | Current status | Deletion or demotion condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `coding-tools` | `packages/runtime-daemon/src/coding-tools.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `packages/runtime-daemon/src/step-module-runner.mjs`, `crates/node/src/bin/ioi-step-module-bridge.rs` | JS daemon tool dispatch with Step/Module projection wrappers and runner boundary | Rust core `step_router` plus workload/WASM backend | Agentgres admitted operation with receipt, refs, heads, and state roots | `abi`, `bridge`, `receipts`, `negative` | `workspace.status` has Rust command-bridge shadow path; live execution still JS authoritative | Rust path passes shadow, gated, and live parity for each migrated tool; JS can no longer append authoritative effects. |
| `approvals-gates` | `packages/runtime-daemon/src/runtime-route-handlers.mjs` | JS daemon routes plus local approval state | Rust core `authority` with wallet.network handoff | authority grant and approval receipt before effect boundary | `bridge`, `negative` | live JS authority surface | JS can only request/render approvals; grants and gate decisions are issued by Rust authority core and wallet.network. |
| `runtime-events-replay-trace` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` | JS daemon envelope/projection code | Rust core `projection` plus Agentgres projection watermarks | replayable projection over admitted operations and receipts | `receipts`, `compositor` | JS projection source | Rust emits canonical projection records consumed by IDE/CLI/SDK. |
| `model-mounting` | `packages/runtime-daemon/src/model-mounting/*` | JS daemon model-mounting store and route policy | Rust core `model_mount` | model invocation receipts, route/custody refs, Agentgres operation | `bridge`, `receipts`, `ctee` | live product daemon state | Rust records route decisions and receipts; JS surfaces are non-authoritative clients. |
| `agentgres-admission` | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs`, `.ioi/agentgres` local state, `docs/architecture/components/agentgres/*` | daemon-local operation-like records plus target canon | Rust core `agentgres_admission` | expected heads, state-root validation, accepted operation admission | `receipts`, `negative` | partial target, split truth risk | no JS path can append accepted operations directly or mutate durable truth without expected heads/state-root binding. |
| `receipt-binding` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/ipc/proto/public/v1/public.proto`, `crates/services/src/agentic/runtime/kernel/receipt_binder.rs` | JS receipts plus Rust/workload receipts; Rust binder primitive exists | Rust core `receipt_binder` | one binder for invocation, result, artifact refs, payload refs, and state roots | `receipts`, `negative` | binder primitive implemented for StepModuleResult; JS receipts still live | every meaningful route family emits receipts through one Rust binder. |
| `ctee-private-workspace` | `docs/architecture/components/daemon-runtime/private-workspace-ctee.md` | canon plus partial product routing | Rust core `ctee` | custody proof, leakage profile, declassification receipt, plaintext-free mount failure | `ctee`, `negative` | planned runtime path | untrusted node plaintext mount fails closed; declassification and private operator paths are receipt-bound. |
| `workload-client-wasm` | `crates/client/src/workload_client/mod.rs`, `crates/vm/wasm/src/lib.rs`, `crates/validator/src/standard/workload/*` | Rust workload/kernel substrate exists below daemon | Rust core `workload_client` plus WASM/service backend | StepModuleResult with workload receipt and state-root binding | `bridge`, `receipts` | substrate exists, not default daemon backend | daemon routes admitted work through StepModuleRunner into Rust/WASM or workload backend. |
| `workflow-compositor` | `packages/agent-ide/src/runtime/*`, `packages/runtime-daemon/src/runtime-event-envelopes.mjs` | IDE/daemon projection shaping | Rust core `projection` consumed by IDE/CLI/SDK | projection checkpoints rebuilt from Agentgres admitted truth | `compositor`, `negative` | rich projection, not final truth source | compositor cannot create accepted truth directly and only renders/replays canonical projections. |
| `worker-service-packages` | `docs/architecture/foundations/common-objects-and-envelopes.md`, `docs/architecture/domains/aiagent/worker-endpoints.md`, `docs/architecture/domains/sas/service-endpoints.md` | target canon plus service/module concepts | Rust core `step_router` plus workload/WASM/AIIP backends | package invocation receipt, authority grant, artifacts, projection | `bridge`, `receipts`, `compositor` | target only | service and worker package invocation uses the shared Step/Module ABI. |
| `meta-improvement` | `crates/services/src/agentic/runtime/kernel/*`, workflow/evaluation docs | partial Rust/IDE signals | Rust core authority plus proposal/eval/approval path | proposal object, eval receipts, approval grant, committed mutation | `receipts`, `negative` | target only | agents cannot self-modify directly; all improvements are proposal-mediated. |
| `rust-daemon-core` | target layout in master guide | not yet extracted as one authoritative core | Rust modules: `authority`, `step_router`, `workload_client`, `model_mount`, `ctee`, `receipt_binder`, `agentgres_admission`, `projection`, `conformance` | one Rust owner for hot-path semantics | all tiers | not extracted | hot-path execution, authority, receipt/state-root binding, cTEE, replay, and conformance are owned by Rust core. |
| `js-facade-retirement` | `packages/runtime-daemon/src/*` | JS is current live daemon implementation | non-authoritative product/API/client facade only where useful | stable protocol APIs into Rust core | `negative`, terminal `hypervisor-conformance` | not retired | every migrated route family removes or demotes old JS authoritative paths and compatibility shims. |

## Cleanup Targets Found In Phase 0

These are not deletions for Slice 0. They are the long-term cleanup targets that
must be retired as the corresponding route family reaches verified parity:

| Cleanup target | Why it must not be permanent | Removal trigger |
| --- | --- | --- |
| Direct JS coding tool dispatch for consequential effects | It is the current split-brain authoritative execution path. | Each tool has ABI coverage, Rust/WASM or workload execution, receipts/state roots, and compositor parity. |
| Daemon-local operation-like truth outside Rust Agentgres admission | It risks duplicate accepted truth. | Agentgres admission enforces expected heads and state-root binding for meaningful transitions. |
| Receipt emission in multiple owners | Duplicate receipt paths make replay and failure analysis ambiguous. | `receipt_binder` owns all accepted receipt/result binding. |
| Model/provider fallback routes outside daemon-owned model mounting | Earlier parity work established daemon-owned mounting/routing as source of truth. | Rust `model_mount` owns route decisions and receipts. |
| Compatibility adapters that can mutate state or emit accepted receipts | Alpha has no need to preserve old route behavior after migration. | Stable protocol APIs exist and migrated route families pass negative conformance. |
| Workflow compositor accepted-truth shortcuts | The IDE should compose and inspect, not admit truth. | compositor projections rebuild from Agentgres operations and Rust projection watermarks. |
| cTEE language without runtime plaintext-failure tests | cTEE is no-plaintext-custody private workspace execution, not encryption-at-rest. | private workspace module path and leakage/declassification tests pass. |

## Command State

The command contract is wired at the repo task-runner layer:

```text
hypervisor-conformance
hypervisor-conformance:docs
hypervisor-conformance:abi
hypervisor-conformance:bridge
hypervisor-conformance:receipts
hypervisor-conformance:ctee
hypervisor-conformance:compositor
hypervisor-conformance:negative
```

Current expected behavior after Slice 4:

| Command | Expected status now | Reason |
| --- | --- | --- |
| `hypervisor-conformance:docs` | pass | Phase 0 inventory, source map, matrix, command wiring, and stale-term guard exist. |
| `hypervisor-conformance:abi` | pass | Step/Module schemas and current coding-tool projection wrappers exist. |
| `hypervisor-conformance:bridge` | pass | daemon StepModuleRunner boundary and fail-closed Rust workload runner selection exist. |
| `hypervisor-conformance:receipts` | pass | Rust StepModule receipt binder exists and the Rust shadow bridge emits a receipt binding. |
| `hypervisor-conformance:ctee` | fail closed | cTEE private workspace module path and plaintext-failure tests are not yet implemented. |
| `hypervisor-conformance:compositor` | fail closed | IDE/CLI/SDK are not yet backed by Rust projection records. |
| `hypervisor-conformance:negative` | fail closed | forbidden-path fixtures are not yet implemented. |
| `hypervisor-conformance` | fail closed | terminal migration is not complete. |
