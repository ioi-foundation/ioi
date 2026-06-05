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

## Implementation Slice 5

```yaml
ImplementationSlice:
  objective: introduce the Rust cTEE Private Workspace module boundary and prove
    plaintext custody fails closed on untrusted nodes
  owner_boundary:
    route_or_surface: cTEE Private Workspace StepModule validation
    authority_gate: StepModule authority fields plus declassification approval
      requirement; wallet.network handoff remains a later authority-core slice
    execution_backend: ctee_operator ABI backend validation
    truth_path: no accepted Agentgres mutation in this slice
    projection_path: no compositor projection upgrade in this slice
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/ctee.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/ctee.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services ctee_private_workspace
      - npm run hypervisor-conformance:ctee
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the cTEE plaintext negative case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - cTEE validation exists in Rust, but full private workspace execution,
        Agentgres admission, and compositor projection remain to be migrated
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 6

```yaml
ImplementationSlice:
  objective: add Rust StepModule projection records and a workflow-compositor
    accepted-truth guard, then emit projection records from the Rust shadow bridge
  owner_boundary:
    route_or_surface: workflow projection record source
    authority_gate: compositor is explicitly rejected as an accepted-truth writer
    execution_backend: Rust command bridge shadow path
    truth_path: projection records derive from StepModuleResult plus receipt
      binding; Agentgres admission is still a later slice
    projection_path: RustProjectionCore emits StepModuleProjectionRecord
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/projection.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi-step-module-bridge.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/projection.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services projection
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:compositor
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the workflow compositor accepted-truth case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - IDE/CLI/SDK still need to consume stable Rust/Agentgres projection APIs
        before JS projection shaping can be demoted
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 7

```yaml
ImplementationSlice:
  objective: add the Rust Agentgres admission guard so accepted operation
    proposals require expected heads, before/after state roots, resulting head,
    and an exact StepModule receipt binding
  owner_boundary:
    route_or_surface: Agentgres operation admission primitive
    authority_gate: unchanged; wallet.network authority handoff remains a later
      authority-core slice
    execution_backend: no execution backend change in this slice
    truth_path: AgentgresAdmissionCore rejects unbound accepted-operation
      proposals before they can become admitted operational truth
    projection_path: admitted records carry the receipt-binding projection
      watermark for Rust projection replay
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services agentgres_admission
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the Agentgres expected-head/state-root case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - daemon-local operation-like records and JS append surfaces still need to
        be routed through the Rust admission core before facade retirement
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 8

```yaml
ImplementationSlice:
  objective: add a Rust receipt-core append guard so accepted receipts cannot be
    appended by daemon JS facades or external adapters outside the receipt binder
  owner_boundary:
    route_or_surface: accepted receipt append primitive
    authority_gate: unchanged; this slice narrows receipt ownership, not wallet
      authority issuance
    execution_backend: no execution backend change in this slice
    truth_path: accepted receipt append records require a StepModule receipt
      binding hash, bound receipt ref, and matching state-root/resulting-head
      fields from the Rust receipt binder
    projection_path: unchanged; projection continues to read receipt-bound
      records from Rust projection/Agentgres watermarks
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/receipt_binder.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
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
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the direct accepted receipt append case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS receipt emission surfaces still need to be routed through the Rust
        receipt binder/admission core before facade retirement
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 9

```yaml
ImplementationSlice:
  objective: add an Agentgres storage-write admission guard so backend writes
    cannot be treated as meaningful payload truth without an ArtifactRef or
    PayloadRef plus receipt linkage
  owner_boundary:
    route_or_surface: storage backend write admission primitive
    authority_gate: unchanged; storage backend writes still require upstream
      authority/policy gates in later route-family migrations
    execution_backend: no execution backend change in this slice
    truth_path: storage write admission records are owned by AgentgresAdmissionCore
      and require content hash, receipt refs, and Agentgres ArtifactRef/PayloadRef
      linkage
    projection_path: unchanged; storage locations remain payload-byte metadata
      below Agentgres-owned refs
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no bypass of wallet.network authority where applicable
    - no accepted transition without receipt/ref/state-root binding
    - no storage backend authority-layer regression
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services agentgres_admission
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the storage backend ArtifactRef/PayloadRef case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - concrete storage writer surfaces still need to call this Rust admission
        guard before JS facade retirement
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 10

```yaml
ImplementationSlice:
  objective: introduce a Rust wallet.network authority-core guard for external
    capability exits so connector/AIIP exits cannot proceed without a
    wallet.network grant and authority receipt
  owner_boundary:
    route_or_surface: external capability exit authority primitive
    authority_gate: WalletAuthorityCore requires wallet.network grant refs and
      authority receipt refs before issuing an exit authority record
    execution_backend: no execution backend change in this slice
    truth_path: authority records are hash-bound Rust outputs that later
      StepModule/Agentgres slices must bind into accepted operations
    projection_path: unchanged; IDE/CLI/SDK still need stable protocol
      projection of authority records
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/authority.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/authority.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - external capability exits require wallet.network authority
    - no accepted transition without receipt/ref/state-root binding
    - no storage backend authority-layer regression
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services authority
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the external capability exit authority case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS connector/capability exit surfaces still need to call this Rust
        authority core and bind the record into receipts/Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 11

```yaml
ImplementationSlice:
  objective: add a Rust L1 settlement trigger guard so IOI L1/app-chain
    commitments cannot be attempted as default runtime settlement
  owner_boundary:
    route_or_surface: L1 settlement admission primitive
    authority_gate: upstream wallet.network/operator/contract authority remains
      required by the trigger source; this slice proves trigger absence fails
      closed
    execution_backend: no execution backend change in this slice
    truth_path: local Agentgres/domain truth remains canonical; L1 admission is
      a sparse public/economic/cross-domain commitment by trigger only
    projection_path: unchanged; L1 admission records are later projection inputs,
      not live operational truth
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/settlement.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/settlement.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - no bypass of daemon execution ownership
    - no default L1 runtime settlement
    - no accepted transition without receipt/ref/state-root binding
    - no storage backend authority-layer regression
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services settlement
      - npm run hypervisor-conformance:negative (expected fail closed overall,
        with the L1 settlement trigger case passing)
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - concrete settlement surfaces still need to call this Rust trigger guard
        and bind the resulting record into receipts/Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 12

```yaml
ImplementationSlice:
  objective: add a Rust StepModuleRouter guard so daemon_js can remain a
    projection/shadow facade during migration but cannot admit authoritative
    mutations
  owner_boundary:
    route_or_surface: StepModule execution admission primitive
    authority_gate: unchanged; existing authority guards still precede effect
      boundaries
    execution_backend: daemon_js is rejected when a result carries Agentgres
      operation refs, state-root/resulting-head mutation, or live projection
      status; Rust/workload backends can carry authoritative transitions
    truth_path: authoritative StepModule transitions must be admitted through
      Rust router plus receipt/Agentgres binders before becoming truth
    projection_path: daemon_js remains projection/shadow-only until facade
      retirement removes the old live JS surfaces
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/step_router.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/step_router.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - direct JS authoritative mutation fails
    - no bypass of daemon execution ownership
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo test -p ioi-services step_router
      - npm run hypervisor-conformance:negative
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - live JS coding/tool/facade surfaces still need to be routed through the
        Rust StepModuleRouter and then demoted or removed after parity
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 13

```yaml
ImplementationSlice:
  objective: route the first Rust command-bridge tool path through
    StepModuleRouterCore and return the router admission record with
    workspace.status shadow output
  owner_boundary:
    route_or_surface: workspace.status Rust command bridge admission chain
    authority_gate: unchanged; existing daemon gates still precede the bridge
    execution_backend: rust_workload_shadow command bridge now performs Rust
      router admission before receipt binding and projection
    truth_path: no accepted Agentgres mutation in this slice; the bridge proves
      StepModuleRouter admission is in the first shadow path
    projection_path: unchanged shadow projection record, now accompanied by
      router_admission evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/node/src/bin/ioi-step-module-bridge.rs
      - crates/services/src/agentic/runtime/kernel/step_router.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge output includes router admission
    - direct JS authoritative mutation fails
    - no accepted transition without receipt/ref/state-root binding
    - no cTEE plaintext-custody regression
  verification:
    commands:
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - workspace.status is still shadowed; live daemon_js execution remains
        until live parity and facade demotion land
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 14

```yaml
ImplementationSlice:
  objective: promote workspace.status to the Rust workload live path so that
    live mode uses the Rust command bridge and does not execute the daemon JS
    coding-tool body
  owner_boundary:
    route_or_surface: workspace.status coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for workspace.status; non-migrated
      tools still fail closed in live mode
    truth_path: no accepted Agentgres mutation in this slice; live status output
      is a StepModule result with router admission, receipt binding, and
      projection evidence
    projection_path: runtime event payload carries the Rust StepModule result
      and router admission
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - workspace.status live path bypasses daemon_js execution
    - non-migrated live tools fail closed
    - bridge output includes router admission
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - other coding tools still use daemon_js until each has Rust/workload
        parity, receipt/admission binding, and live-mode tests
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 15

```yaml
ImplementationSlice:
  objective: promote file.inspect to the Rust workload live path and return its
    inspect result from the Rust command bridge rather than the daemon JS coding
    tool body
  owner_boundary:
    route_or_surface: file.inspect coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for file.inspect; non-migrated tools
      still fail closed in live mode
    truth_path: no accepted Agentgres mutation in this slice; read-only inspect
      output is a StepModule result with router admission, receipt binding, and
      projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized file.inspect observation
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/step-module-runner.mjs
    rust_core:
      - crates/node/src/bin/ioi-step-module-bridge.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - packages/runtime-daemon/src/step-module-runner.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - file.inspect live path bypasses daemon_js execution
    - file.inspect cannot read outside the workspace root
    - non-migrated live tools fail closed
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - node --test packages/runtime-daemon/src/step-module-runner.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - mutating coding tools still use daemon_js until each has Rust/workload
        execution, receipt/admission binding, parity, and live-mode tests
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 16

```yaml
ImplementationSlice:
  objective: promote git.diff to the Rust workload live path and return bounded
    diff output from the Rust command bridge rather than the daemon JS coding
    tool body
  owner_boundary:
    route_or_surface: git.diff coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for git.diff; mutating tools still
      fail closed in live mode
    truth_path: no accepted Agentgres mutation in this slice; read-only Git diff
      output is a StepModule result with router admission, receipt binding, and
      projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized git.diff observation
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
    rust_core:
      - crates/node/src/bin/ioi-step-module-bridge.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - Rust unit tests in crates/node/src/bin/ioi-step-module-bridge.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - git.diff live path bypasses daemon_js execution
    - git.diff cannot pathspec outside the workspace root
    - mutating live tools still fail closed
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge git_diff
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - mutating coding tools, test execution, diagnostics, artifact retrieval,
        and computer-use lease requests still need Rust/workload execution,
        receipt/admission binding, parity, and live-mode tests
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 17

```yaml
ImplementationSlice:
  objective: extract the Rust StepModule command-bridge implementation out of
    the binary wrapper before adding more live tool routes
  owner_boundary:
    route_or_surface: Rust command bridge implementation hygiene
    authority_gate: unchanged; migrated tool bridge responses still pass through
      StepModuleRouterCore before receipt binding and projection
    execution_backend: unchanged; workspace.status, git.diff, and file.inspect
      remain rust_workload_live-capable through the same command entry point
    truth_path: unchanged; this slice carries no accepted Agentgres mutation
    projection_path: unchanged; projection evidence still comes from the shared
      StepModule response path
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/node/src/bin/ioi-step-module-bridge.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - command bridge binary is only stdin/stdout glue
    - migrated bridge module still routes workspace.status, git.diff, and
      file.inspect through StepModuleRouterCore
    - bridge output still includes router admission, receipt binding, and
      projection evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge git_diff
      - cargo test -p ioi-node --bin ioi-step-module-bridge file_inspect
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: behavior-preserving refactor
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - the command bridge is still an interim migration bridge until Rust
        workload_client owns the live transport
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 18

```yaml
ImplementationSlice:
  objective: replace the workspace.status shadow-only bridge response with a
    real Rust workspace status observation so the live path returns the same
    tool payload shape as the retired daemon JS body
  owner_boundary:
    route_or_surface: workspace.status coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for workspace.status, with direct Rust
      Git status observation and no daemon_js body execution
    truth_path: no accepted Agentgres mutation in this slice; read-only status
      output remains a StepModule result with router admission, receipt binding,
      and projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized workspace.status observation
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - workspace.status live path bypasses daemon_js execution
    - workspace.status Rust output includes git availability, branch,
      porcelain hash, changed files, and counts
    - workspace.status no longer uses the shadow-only bridge branch
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge workspace_status
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: replaces shadow-only observation with live
      Rust payload parity for workspace.status
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - the response still uses the bridge envelope's shadow_observation field
        until the bridge envelope itself is renamed or replaced by workload_client
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 19

```yaml
ImplementationSlice:
  objective: promote the lsp.diagnostics node.check backend to the Rust workload
    live path while unsupported diagnostics backends fail closed
  owner_boundary:
    route_or_surface: lsp.diagnostics coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for lsp.diagnostics when commandId is
      node.check; auto and typescript.check remain explicitly unsupported until
      their Rust implementations land
    truth_path: no accepted Agentgres mutation in this slice; diagnostic command
      output remains a StepModule result with router admission, receipt binding,
      and projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized lsp.diagnostics observation
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - lsp.diagnostics node.check live path bypasses daemon_js execution
    - node.check command execution is bounded and workspace path checked
    - unsupported diagnostics backends fail closed instead of falling back to JS
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge lsp_diagnostics
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: node.check diagnostic payload parity for clean,
      syntax-error, and unsupported-backend fail-closed cases
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - lsp.diagnostics auto and typescript.check still need Rust/workload
        implementations before the JS diagnostics body can be fully retired
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 20

```yaml
ImplementationSlice:
  objective: promote the test.run node.test backend to the Rust workload live
    path while unsupported test command backends fail closed
  owner_boundary:
    route_or_surface: test.run coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for test.run when commandId is
      node.test; npm.test, cargo.test, and cargo.check remain explicitly
      unsupported until their Rust implementations land
    truth_path: no accepted Agentgres mutation in this slice; test execution
      output remains a StepModule result with router admission, receipt binding,
      and projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized test.run observation
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - test.run node.test live path bypasses daemon_js execution
    - node.test command execution is bounded and workspace path checked
    - unsupported test command backends fail closed instead of falling back to JS
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge test_run
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: node.test payload parity for passing, failing,
      and unsupported-backend fail-closed cases
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - test.run npm.test, cargo.test, and cargo.check still need Rust/workload
        implementations before the JS test runner body can be fully retired
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 21

```yaml
ImplementationSlice:
  objective: promote the remaining test.run npm.test, cargo.test, and
    cargo.check backends to the Rust workload live path and remove the temporary
    non-node test backend unsupported shim
  owner_boundary:
    route_or_surface: test.run coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for all allowlisted test.run command
      ids: node.test, npm.test, cargo.test, and cargo.check
    truth_path: no accepted Agentgres mutation in this slice; test execution
      output remains a StepModule result with router admission, receipt binding,
      and projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized test.run observation for every
      allowlisted test command backend
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - test.run npm.test, cargo.test, and cargo.check execute through Rust live
      command mapping
    - test.run command execution is bounded and workspace cwd/path checked
    - disallowed test command ids fail closed instead of falling back to JS
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge test_run
      - cargo test -p ioi-node --bin ioi-step-module-bridge
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: npm.test, cargo.test, cargo.check, node.test,
      and disallowed-command fail-closed cases
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS testRunTool remains as a legacy fallback until JS facade retirement
        once Rust workload live mode is the only daemon execution configuration
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 22

```yaml
ImplementationSlice:
  objective: promote lsp.diagnostics auto and typescript.check to the Rust
    workload live path and remove the temporary diagnostics unsupported-backend
    shim
  owner_boundary:
    route_or_surface: lsp.diagnostics coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live for all allowlisted diagnostics
      command ids: auto, node.check, and typescript.check
    truth_path: no accepted Agentgres mutation in this slice; diagnostic command
      output remains a StepModule result with router admission, receipt binding,
      and projection evidence
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, and normalized diagnostics observation for every
      allowlisted diagnostics backend
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - lsp.diagnostics auto routes JavaScript paths to Rust node.check
    - lsp.diagnostics typescript.check executes local tsc from Rust when present
    - missing local tsc returns a degraded Rust result without daemon_js fallback
    - bridge output includes router admission, receipt binding, and projection
      evidence
    - no accepted transition without receipt/ref/state-root binding
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge lsp_diagnostics
      - cargo test -p ioi-node --bin ioi-step-module-bridge
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: auto JavaScript path routing, TypeScript
      diagnostic parsing, and missing-local-tsc degraded Rust result
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS lspDiagnosticsTool remains as a legacy fallback until JS facade
        retirement once Rust workload live mode is the only daemon execution
        configuration
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 23

```yaml
ImplementationSlice:
  objective: promote file.apply_patch to the Rust workload live path with
    state-root-bound Agentgres admission for real workspace mutations
  owner_boundary:
    route_or_surface: file.apply_patch coding tool invocation
    authority_gate: existing budget/approval gates still run before live bridge
      execution
    execution_backend: rust_workload_live applies replace/append/prepend edits
      directly; daemon JS no longer performs the workspace write in live mode
    truth_path: non-dry-run changed patches emit Agentgres operation refs,
      expected heads, state_root_before, state_root_after, resulting_head,
      receipt binding, and Agentgres admission from Rust
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, receipt binding, Agentgres admission, normalized patch
      observation, and daemon facade snapshot/diagnostics projection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - file.apply_patch live path bypasses daemon_js mutation
    - Rust patch writes are workspace path checked and edit bounded
    - non-dry-run changed patches carry state-root and resulting-head binding
    - Rust bridge emits router admission, receipt binding, and Agentgres
      admission for meaningful patch transitions
    - dry-run patches execute through Rust without accepted Agentgres mutation
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge file_apply_patch
      - cargo test -p ioi-node --bin ioi-step-module-bridge
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: Rust patch write/admission, Rust dry-run
      no-transition, daemon snapshot facade over Rust patch result
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS fileApplyPatchTool remains as a legacy fallback until JS facade
        retirement once Rust workload live mode is the only daemon execution
        configuration
      - daemon workspace snapshot and post-edit diagnostics remain facade
        projections over the Rust patch result, not the mutation owner
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 24

```yaml
ImplementationSlice:
  objective: promote artifact.read and tool.retrieve_result to the Rust
    workload live path as read-only StepModule projections over daemon
    data-plane artifact refs
  owner_boundary:
    route_or_surface: artifact.read and tool.retrieve_result coding tool
      invocation
    authority_gate: existing budget/approval gates still run before the live
      bridge execution path
    execution_backend: rust_workload_live owns StepModule dispatch, result
      normalization, receipt binding, router admission, and projection;
      daemon JS only supplies the artifact-store payload as a data-plane handle
    truth_path: read-only retrieval produces no Agentgres transition, but the
      Rust bridge fails closed without the daemon-provided ArtifactRef/Payload
      payload and binds receipts over the normalized observation
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, receipt binding, normalized artifact/result observation,
      artifact refs, and Rust-live backend evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/coding-tools.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - artifact.read live path bypasses daemon_js execution while still using
      the daemon artifact store as a non-authoritative data-plane source
    - tool.retrieve_result live path bypasses daemon_js execution and passes the
      resolved result payload into Rust for normalization
    - Rust bridge rejects retrieval without rustWorkloadDataPlane payload
    - Rust bridge recomputes contentHash and forces shellFallbackUsed false for
      normalized retrieval observations
    - read-only retrieval emits no Agentgres admission
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge artifact_read
      - cargo test -p ioi-node --bin ioi-step-module-bridge tool_retrieve_result
      - cargo test -p ioi-node --bin ioi-step-module-bridge
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: Rust retrieval projection over daemon
      data-plane prefetch, Rust fail-closed missing-payload test
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS artifactReadTool and toolRetrieveResultTool remain as legacy fallback
        helpers until JS facade retirement once Rust workload live mode is the
        only daemon execution configuration
      - daemon artifact-store read/retrieve remains a data-plane adapter until
        ArtifactRef/PayloadRef storage APIs move behind stable protocol calls
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 25

```yaml
ImplementationSlice:
  objective: promote computer_use.request_lease to the Rust workload live path
    as the canonical governed lease-request projection
  owner_boundary:
    route_or_surface: computer_use.request_lease coding tool invocation
    authority_gate: existing budget/approval gates still run before the live
      bridge path; Rust result records wallet.network authority boundary and
      approval-required state before any provider execution can occur
    execution_backend: rust_workload_live owns StepModule dispatch, lane/session
      normalization, provider-row selection, requestRef generation, receipt
      binding, router admission, and projection
    truth_path: read-only lease request records no Agentgres mutation and no
      acquired provider lease; act-capable requests remain fail-closed until
      wallet.network/approval-backed execution paths issue grants and receipts
    projection_path: runtime event payload carries the Rust StepModule result,
      router admission, receipt binding, normalized computer-use lease request,
      provider registry row, and wallet.network authority-boundary evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/computer_use.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - computer_use.request_lease live path bypasses daemon_js execution
    - Rust bridge composes the governed lease request and provider registry row
    - action-capable requests without approval record wallet.network authority
      requirement before execution
    - unavailable provider hints remain fail-closed without mounting an adapter
    - read-only lease request projection emits no Agentgres admission
  verification:
    commands:
      - cargo test -p ioi-node --bin ioi-step-module-bridge computer_use_request_lease
      - cargo test -p ioi-node --bin ioi-step-module-bridge
      - cargo check -p ioi-node --bin ioi-step-module-bridge
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: Rust lease-request projection, Rust
      unavailable-provider fail-closed test, daemon live-mode no-daemon-js test
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS computerUseLeaseRequestTool remains as a legacy fallback until JS
        facade retirement once Rust workload live mode is the only daemon
        execution configuration
      - provider-specific computer-use execution remains outside this coding
        tool until wallet.network-issued grants, provider leases, and receipts
        are routed through the Rust authority core
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 26

```yaml
ImplementationSlice:
  objective: introduce the Rust model_mount route-decision core so model route
    selection has a Rust-owned admission boundary before JS facade integration
  owner_boundary:
    route_or_surface: model-mounting route decision and provider/model endpoint
      selection
    authority_gate: Rust validates resolved model/provider/endpoint refs,
      receipt refs, policy hash, idempotency, and private workspace cTEE custody
      constraints before a route decision can be admitted
    execution_backend: no provider invocation changes in this slice; this
      creates the Rust core boundary that daemon JS model-mounting routes must
      call before facade retirement
    truth_path: route decisions are Rust hash-bound records with receipt refs
      and custody metadata; unresolved `auto` model selectors are rejected
      before provider invocation
    projection_path: unchanged in product daemon for this slice; conformance
      now verifies the Rust model_mount owner exists and rejects plaintext cTEE
      routes
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - Rust unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust model_mount core admits resolved route decisions with receipt refs
    - unresolved `auto` model selectors fail before provider invocation
    - route decisions without receipts fail closed
    - private_workspace_ctee routes require custody refs and cannot allow node
      plaintext
    - conformance detects the Rust model_mount owner boundary
  verification:
    commands:
      - cargo test -p ioi-services model_mount
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS model-mounting route-decision/store surfaces still need to call
        ModelMountCore and bind records into receipts/Agentgres admission before
        JS facade retirement
      - provider invocation drivers remain JS-owned until model invocation
        envelopes and provider receipts are promoted to Rust core ownership
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 27

```yaml
ImplementationSlice:
  objective: route live daemon model-route-selection receipts through the Rust
    model_mount admission core before provider invocation
  owner_boundary:
    route_or_surface: model-mounting route decision receipt creation
    authority_gate: daemon route receipt creation now requires a Rust
      model_mount command-bridge admission record and fails closed when the
      bridge is unconfigured
    execution_backend: provider invocation drivers remain JS-owned in this
      slice, but route decisions are admitted through the Rust bridge operation
      `admit_model_mount_route_decision` before any provider request body is
      sent
    truth_path: route-selection receipts carry the Rust modelMountRouteDecision
      record, receipt refs, policy hash, idempotency key, workflow refs, and
      cTEE custody posture; the Rust record is bound to the actual precomputed
      route-selection receipt id
    projection_path: existing model-route-decision projections now have a
      Rust-admitted decision record embedded in the same receipt they already
      project from
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/receipt-operations.mjs
      - packages/runtime-daemon/src/model-mounting/routes.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/routes.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - JS route receipt creation calls Rust model_mount admission
    - model route receipts fail closed without the Rust admission runner
    - model route receipts fail closed without a precomputed receipt id
    - model=auto is resolved to the selected endpoint model before Rust
      admission
    - Rust bridge exposes and tests `admit_model_mount_route_decision`
    - conformance bridge tier detects the live model_mount route-decision bridge
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - cargo test -p ioi-node bridge_admits_model_mount_route_decision_through_rust_core
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider invocation drivers still execute in JS after the Rust-admitted
        route decision; next slices must promote model invocation envelopes,
        provider receipts, and result binding into Rust ownership
      - receipt persistence itself remains the model-mounting JS store path
        until Agentgres admission and receipt_binder integration are promoted
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 28

```yaml
ImplementationSlice:
  objective: route model invocation receipts through Rust model_mount admission
    before JS persistence
  owner_boundary:
    route_or_surface: model invocation and native-stream-start receipt creation
    authority_gate: daemon invocation receipt creation now requires a Rust
      model_mount invocation admission record bound to the prior route decision,
      route receipt, and the exact precomputed invocation receipt id
    execution_backend: provider invocation drivers still execute in JS in this
      slice; Rust now owns the invocation receipt admission boundary after
      provider result materialization and before receipt persistence
    truth_path: invocation receipts carry the Rust modelMountInvocationAdmission
      record with route_decision_ref, route_receipt_ref,
      invocation_receipt_ref, policy/input/output hashes, authority refs,
      provider/backend evidence refs, and cTEE custody posture
    projection_path: existing invocation projections continue reading the
      canonical model_invocation receipts, now with Rust-admitted invocation
      records embedded
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust model_mount core admits invocation records only with route and
      invocation receipt refs bound
    - model invocation receipts fail closed without precomputed receipt ids
    - completed, coalesced, and native stream-start receipts embed Rust
      invocation admission records
    - Rust bridge exposes and tests `admit_model_mount_invocation`
    - conformance bridge and receipts tiers detect the invocation admission
      core and live daemon bridge
  verification:
    commands:
      - cargo test -p ioi-services model_mount
      - cargo test -p ioi-node bridge_admits_model_mount_invocation_through_rust_core
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - route-decision-only admission runner naming and env aliases were
        retired; model-mount admission now uses the canonical
        `IOI_MODEL_MOUNT_ADMISSION_*` bridge contract
      - provider invocation drivers remain JS-owned until model invocation
        execution envelopes and provider request/response semantics move behind
        Rust workload/model_mount ownership
      - receipt persistence remains the model-mounting JS store path until
        Agentgres admission and receipt_binder integration are promoted
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 29

```yaml
ImplementationSlice:
  objective: bind model invocation receipts through Rust receipt_binder before
    JS store persistence
  owner_boundary:
    route_or_surface: model invocation, coalesced invocation, and native stream
      start receipt persistence
    authority_gate: daemon invocation receipt creation now constructs a
      `model_mount` StepModule invocation/result and requires Rust
      StepModuleRouter, receipt_binder, accepted-receipt append, and projection
      records before the JS model-mounting store writes the receipt envelope
    execution_backend: provider invocation drivers still execute in JS in this
      slice; Rust owns the accepted receipt binding around the completed model
      invocation result
    truth_path: invocation receipts carry Rust receipt_binding,
      accepted_receipt_append, StepModule invocation/result, router admission,
      and projection records in addition to the Rust model_mount admission
      record
    projection_path: existing invocation projections continue reading the
      canonical model_invocation receipts, now with Rust StepModule projection
      records embedded
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/step-module-abi.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/step-module-abi.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - model mount receipts project into the shared Step/Module ABI
    - Rust bridge exposes and tests `bind_model_mount_invocation_receipt`
    - model invocation receipts fail closed without Rust receipt binding support
    - completed, coalesced, and native stream-start receipts embed Rust
      receipt_binding and accepted_receipt_append records before JS persistence
    - conformance bridge and receipts tiers detect the live receipt binding
      path
  verification:
    commands:
      - cargo test -p ioi-node bridge_binds_model_mount_invocation_receipt_through_rust_core
      - node --test packages/runtime-daemon/src/step-module-abi.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:abi
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider invocation drivers remain JS-owned until model invocation
        execution envelopes and provider request/response semantics move behind
        Rust workload/model_mount ownership
      - receipt envelopes still persist through the model-mounting JS store;
        next slices must promote durable Agentgres admission/state-root binding
        and demote the JS store to a facade/cache
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 30

```yaml
ImplementationSlice:
  objective: admit model invocation receipt operations through Rust
    Agentgres admission and state-root binding before JS store persistence
  owner_boundary:
    route_or_surface: model invocation, coalesced invocation, and native stream
      start receipt operation admission
    authority_gate: daemon invocation receipt creation must derive the current
      model-mounting operation head, submit expected heads and state roots into
      the Rust bridge, and fail closed without that Agentgres head
    execution_backend: provider invocation drivers still execute in JS in this
      slice; Rust owns StepModule routing, receipt binding, accepted-receipt
      append, Agentgres admission, and projection records for the completed
      model invocation result
    truth_path: invocation receipts carry Agentgres operation refs,
      state_root_before, state_root_after, resulting_head, and the Rust
      agentgres_admission record before the JS model-mounting store writes the
      receipt envelope
    projection_path: existing invocation projections continue reading the
      canonical model_invocation receipts, now with Rust Agentgres admission and
      projection watermarks embedded
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - model invocation StepModule results include Agentgres operation refs,
      expected heads, state roots, and resulting heads
    - Rust bridge emits `agentgres_admission` for model invocation receipt
      binding requests with operation refs
    - model invocation receipts fail closed without a current model-mounting
      Agentgres operation head
    - conformance bridge and receipts tiers detect Agentgres admission on the
      live model invocation receipt path
  verification:
    commands:
      - cargo test -p ioi-node bridge_binds_model_mount_invocation_receipt_through_rust_core
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider invocation drivers remain JS-owned until model invocation
        execution envelopes and provider request/response semantics move behind
        Rust workload/model_mount ownership
      - receipt envelopes still persist through the model-mounting JS store;
        next slices must demote that store to a projection/cache and ensure no
        JS path can append accepted operations directly
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 31

```yaml
ImplementationSlice:
  objective: make direct JS model invocation receipt appends fail closed unless
    the receipt already carries Rust receipt_binder and Agentgres admission
  owner_boundary:
    route_or_surface: model-mounting receipt store persistence for accepted
      model invocation and coalesced model invocation receipts
    authority_gate: the JS store refuses to persist or append operation-log
      records for accepted model invocation receipts unless the receipt details
      contain Rust receipt binding, accepted-receipt append, Agentgres
      admission, operation ref, state roots, and resulting head
    execution_backend: provider invocation drivers still execute in JS in this
      slice; direct JS persistence is demoted behind the already-bound Rust
      receipt/admission proof
    truth_path: model invocation receipt operation append is no longer possible
      through the store alone; it must be preceded by Rust receipt_binder and
      Agentgres admission
    projection_path: existing model-mounting projections continue reading the
      receipt store, which now rejects unbound accepted invocation receipts
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - direct JS store write of accepted model invocation receipt fails closed
      before file persistence and operation append
    - accepted model invocation receipt persistence requires Rust
      receipt_binder ref, accepted append hash, Agentgres admission hash,
      operation ref, state roots, and resulting head
    - conformance receipts tier detects the direct-store append guard
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider invocation drivers remain JS-owned until model invocation
        execution envelopes and provider request/response semantics move behind
        Rust workload/model_mount ownership
      - the JS model-mounting store still writes projection/cache receipt
        envelopes after Rust admission; future slices must move broader
        operation-log ownership into Rust Agentgres admission and remove any
        remaining direct append surface for meaningful transitions
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 32

```yaml
ImplementationSlice:
  objective: route native stream completion receipts through Rust model_mount,
    receipt_binder, and Agentgres admission before JS store persistence
  owner_boundary:
    route_or_surface: native model stream completion receipt creation
    authority_gate: stream completion now precomputes the completion receipt id,
      builds a model_mount invocation admission request against the original
      route decision, binds the StepModule result through Rust receipt_binder,
      and fails closed without Rust receipt binding
    execution_backend: provider streaming still executes in JS in this slice;
      the terminal completion envelope is no longer a JS-only accepted receipt
    truth_path: stream completion receipts carry Rust model_mount admission,
      receipt_binding, accepted_receipt_append, Agentgres admission,
      operation ref, state roots, and resulting head
    projection_path: conversation state continues to reference the completion
      receipt id, which is now Rust-bound before the conversation projection is
      finalized
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/conversation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - native stream completion receipts fail closed without Rust receipt binding
    - stream completion receipts include StepModule invocation/result,
      Agentgres operation refs, state roots, and resulting head
    - JS model-mounting store rejects unbound stream completion receipt writes
    - conformance receipts tier detects the stream completion binder path
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider streaming still runs in JS until provider request/response
        execution moves behind Rust workload/model_mount ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 33

```yaml
ImplementationSlice:
  objective: require Rust model_mount provider-execution admission before JS
    provider driver invocation
  owner_boundary:
    route_or_surface: model provider request and native stream-start execution
      boundary
    authority_gate: provider requests now build a model_mount provider-execution
      admission request with route decision refs, route receipt refs, policy/input
      hashes, wallet authority refs, cTEE custody refs, backend evidence, and
      stream status before calling the JS provider driver
    execution_backend: provider drivers still execute in JS in this slice; the
      provider execution envelope is admitted by Rust model_mount first and fails
      closed when that admission path is missing
    truth_path: model invocation and stream-start receipts carry the Rust
      provider_execution ref/hash alongside the existing invocation admission,
      receipt_binder, accepted_receipt_append, and Agentgres admission metadata
    projection_path: existing model-mounting projections continue reading the
      accepted receipt envelope, now with provider-execution admission evidence
      available for replay and inspection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
  conformance_checks:
    - Rust model_mount core exposes a provider-execution schema, record, hash,
      route receipt binding guard, unresolved-auto-model guard, and cTEE
      custody/plaintext guard
    - Rust bridge exposes and tests `admit_model_mount_provider_execution`
    - JS model invocation and native stream-start paths fail closed before the
      provider driver call when provider-execution admission is unavailable
    - model invocation receipts include `modelMountProviderExecutionRef` and
      provider-execution evidence refs
    - conformance bridge and receipts tiers detect the provider-execution core
      and live daemon bridge path
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services model_mount
      - cargo test -p ioi-node bridge_admits_model_mount_provider_execution_through_rust_core
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - provider request/response execution still runs in JS after Rust
        provider-execution admission; a later slice must move the provider
        driver/workload call itself behind Rust workload_client/model_mount
        execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 34

```yaml
ImplementationSlice:
  objective: execute the deterministic fixture model provider backend through
    Rust model_mount instead of the JS provider driver
  owner_boundary:
    route_or_surface: fixture/local-folder model provider invocation
    authority_gate: fixture provider requests still require Rust
      provider-execution admission first, then the daemon builds a
      provider-invocation request tied to that admission ref/hash before any
      provider output is produced
    execution_backend: `rust_model_mount_fixture` now computes the fixture
      provider output, token envelope, backend ids, evidence refs, and invocation
      hash; JS driver execution for that migrated backend fails closed when the
      Rust execution bridge is unavailable
    truth_path: existing model invocation receipts carry the Rust
      provider-execution ref plus Rust fixture provider invocation evidence
      before invocation admission, receipt_binder, accepted_receipt_append, and
      Agentgres admission
    projection_path: model-mounting projections continue reading accepted
      receipts; fixture provider invocations now expose Rust invocation evidence
      for replay/inspection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
  conformance_checks:
    - Rust model_mount core exposes a provider-invocation schema, result hash,
      fixture backend execution, unsupported-backend guard, and stream guard
    - Rust bridge exposes and tests
      `execute_model_mount_fixture_provider_invocation`
    - JS fixture/local-folder invocation fails closed before any JS provider
      driver call when Rust provider-invocation execution is unavailable
    - non-migrated providers still run behind provider-execution admission until
      their concrete Rust execution backends are migrated
    - conformance bridge and receipts tiers detect the Rust fixture provider
      invocation path
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services model_mount
      - cargo test -p ioi-node bridge_executes_model_mount_fixture_provider_invocation_through_rust_core
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - hosted/openai-compatible, native-local streaming, Ollama, LM Studio,
        llama.cpp, and vLLM provider request/response execution still run in JS
        after Rust provider-execution admission; later slices must move each
        concrete provider/workload backend behind Rust workload_client/model_mount
        execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 35

```yaml
ImplementationSlice:
  objective: admit non-migrated model provider driver results through Rust
    model_mount before accepted model invocation receipts
  owner_boundary:
    route_or_surface: hosted/openai-compatible, Ollama, LM Studio, llama.cpp,
      vLLM, and other not-yet-migrated non-stream model provider results
    authority_gate: provider calls still require Rust provider-execution
      admission first; non-migrated driver outputs now also require a Rust
      provider-result admission record bound to the same provider-execution
      ref/hash before receipt admission continues
    execution_backend: concrete non-fixture provider request/response transport
      may still run in JS during migration, but the result is explicitly marked
      `js_provider_driver_observation` and is not accepted truth until Rust
      validates the output hash, route receipt, request hash, stream status, and
      admitted provider-execution record
    truth_path: model invocation receipts now carry Rust provider-execution refs,
      migrated fixture invocation evidence, and for non-migrated drivers a Rust
      provider-result admission ref/hash before invocation admission,
      receipt_binder, accepted_receipt_append, and Agentgres admission
    projection_path: model-mounting projections continue reading accepted
      receipts; non-migrated provider results expose Rust admission evidence for
      replay/inspection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - Rust bridge unit test in crates/node/src/bin/ioi_step_module_bridge/mod.rs
  conformance_checks:
    - Rust model_mount core exposes a provider-result schema, ref/hash, output
      hash validation, unsupported-backend guard, and provider-execution binding
    - Rust bridge exposes and tests `admit_model_mount_provider_result`
    - JS non-migrated provider drivers fail closed before provider calls when
      Rust provider-result admission is unavailable
    - accepted model invocation receipts include provider-result admission refs
      for non-migrated driver observations
    - conformance bridge and receipts tiers detect the Rust provider-result path
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services model_mount
      - cargo test -p ioi-node bridge_admits_model_mount_provider_result_through_rust_core
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - hosted/openai-compatible, native-local streaming, Ollama, LM Studio,
        llama.cpp, and vLLM request/response transports still run in JS as
        explicitly admitted observations until each concrete backend moves
        behind Rust workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 36

```yaml
ImplementationSlice:
  objective: admit native model stream-start provider observations through Rust
    model_mount before accepted stream-start receipts
  owner_boundary:
    route_or_surface: native provider stream-start path for non-migrated
      providers, including native-local streaming and hosted/native stream APIs
    authority_gate: stream starts still require Rust provider-execution admission
      first; the daemon now also requires Rust provider-result admission support
      before any JS stream driver call can produce a stream handle
    execution_backend: concrete provider stream transport may still run in JS
      during migration, but the stream-start observation is explicitly marked
      `js_provider_driver_observation` and is not accepted truth until Rust
      validates empty-output hash, token envelope, stream status, request hash,
      route receipt, and admitted provider-execution ref/hash
    truth_path: stream-start model invocation receipts now carry Rust
      provider-execution refs plus Rust provider-result admission refs before
      invocation admission, receipt_binder, accepted_receipt_append, and
      Agentgres admission
    projection_path: stream-start projections continue reading accepted
      receipts; native stream starts expose Rust provider-result admission
      evidence for replay/inspection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
      - docs/architecture/_meta/implementation-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
  conformance_checks:
    - JS stream-start path fails closed before any stream driver call when Rust
      provider-result admission is unavailable
    - stream-start provider-result request carries `stream_status: started`,
      empty output hash, token count, provider response kind, and bound
      provider-execution record
    - Rust model_mount admits stream-start provider observations only when the
      stream status matches the admitted provider-execution record
    - conformance bridge and receipts tiers detect the stream-start
      provider-result admission path
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services model_mount
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - native stream byte transport and stream frame production still run in JS
        until the concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 37

```yaml
ImplementationSlice:
  objective: retire the duplicate JS stream request-shape operation append now
    that stream-start provider observations are Rust-admitted
  owner_boundary:
    route_or_surface: native provider stream-start request-shape evidence
    authority_gate: unchanged; stream starts require Rust provider-execution
      admission and Rust provider-result admission before accepted receipts
    execution_backend: concrete stream transport may still run in JS during
      migration, but request-shape provenance is carried by Rust provider
      execution/result admission instead of a direct JS `appendOperation`
    truth_path: stream-start receipts and Agentgres admissions advance from the
      accepted model invocation transition; the daemon no longer appends a
      separate `model.provider_stream_request_shape` operation-like record
    projection_path: projections continue reading accepted receipts and their
      Rust provider-execution/provider-result evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/provider-protocol.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/provider-protocol.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - stream-start path has no `model.provider_stream_request_shape`
      appendOperation call
    - stream-start path still requires Rust provider-result admission before the
      provider stream driver call
    - stream-start receipt evidence includes provider-result admission refs
    - legacy request-shape trace summarizer export is removed with the retired
      append path
    - conformance bridge and receipts tiers detect the retired append surface
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-protocol.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - native stream byte transport and stream frame production still run in JS
        until the concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 38

```yaml
ImplementationSlice:
  objective: retire the post-admission native stream downgrade into a second
    non-stream JS invocation
  owner_boundary:
    route_or_surface: native provider stream-start result handling
    authority_gate: once Rust provider-execution admission has accepted a
      stream-start boundary, the daemon must either receive a provider stream
      handle and admit the stream-start provider result, or fail closed
    execution_backend: concrete stream transport still runs in JS during
      migration, but a missing stream result no longer re-enters
      `state.invokeModel(... stream: false)` after the admitted stream boundary
    truth_path: no accepted non-stream model invocation can be created as a
      fallback from an already-admitted native stream-start attempt
    projection_path: projections continue reading accepted receipts; rejected
      native stream-start attempts produce no accepted model invocation receipt
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - admitted native stream-start attempts throw
      `model_mount_native_stream_result_required` when the driver returns no
      stream handle
    - the old `providerResult` no-stream branch cannot call
      `state.invokeModel(... stream: false)`
    - the negative unit test proves no fallback invocation, operation append, or
      provider-result admission occurs for a missing stream handle
    - bridge conformance detects the retired downgrade surface
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - pre-admission fallback from a provider with no native streaming support
        to non-stream invocation still remains until stream capability selection
        is fully modeled in Rust route/provider admission
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 39

```yaml
ImplementationSlice:
  objective: retire pre-admission native stream downgrades into non-stream JS
    invocation
  owner_boundary:
    route_or_surface: native stream capability selection before stream-start
      provider-execution admission
    authority_gate: a stream request that selects a Rust provider backend
      without stream execution or a provider driver without stream capability
      now fails closed before any provider execution admission, provider-result
      admission, operation append, or fallback invocation
    execution_backend: concrete native stream byte transport still runs in JS
      during migration, but `startModelStream` no longer calls
      `state.invokeModel(... stream: false)` for any selected provider
    truth_path: stream requests cannot create accepted non-stream invocation
      receipts through compatibility downgrades
    projection_path: failed native stream capability checks produce no accepted
      model invocation receipt or projection truth
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - selected Rust provider backends without native stream execution throw
      `model_mount_native_stream_backend_required`
    - selected providers without stream-capable drivers throw
      `model_mount_native_stream_capability_required`
    - `startModelStream` contains no
      `state.invokeModel(... stream: false)` downgrade branch
    - the negative unit tests prove no fallback invocation, operation append, or
      provider admission occurs before failing closed
    - bridge conformance detects the retired pre-admission downgrade surface
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 40

```yaml
ImplementationSlice:
  objective: retire OpenAI-compatible `responses` to `chat.completions`
    fallback translation
  owner_boundary:
    route_or_surface: non-stream OpenAI-compatible provider invocation for
      `responses`
    authority_gate: provider-execution admission still precedes the JS provider
      call, and provider-result admission still follows successful provider
      output; a missing `/responses` endpoint now fails closed before any
      translated chat-completions result can be admitted
    execution_backend: concrete OpenAI-compatible HTTP transport still runs in
      JS during migration, but it no longer recursively retries a `responses`
      invocation as `chat.completions` or emits `compatTranslation:
      chat_completions`
    truth_path: a `responses` invocation can only admit a `responses` provider
      result, not a chat-completions provider result disguised as compatibility
      translation
    projection_path: projections continue reading accepted model invocation
      receipts; failed `/responses` calls produce no accepted provider result or
      model invocation receipt
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs
      - packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs
      - packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - OpenAI-compatible `responses` failures throw `external_blocker`
      instead of retrying `/chat/completions`
    - provider driver source contains no `allowResponsesFallback`
    - provider driver source contains no `compatTranslation: "chat_completions"`
    - LM Studio, vLLM, and llama.cpp wrappers no longer pass a
      responses-fallback option into the shared OpenAI-compatible driver
    - bridge conformance detects the retired fallback translation
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - concrete non-fixture provider request/response transport still runs in
        JS as Rust-admitted observations until moved behind Rust
        workload_client/model_mount execution ownership
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 41

```yaml
ImplementationSlice:
  objective: retire model-mounting protocol response compatibility re-exports
  owner_boundary:
    route_or_surface: OpenAI-compatible protocol response shaping for
      `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`,
      `/v1/completions`, and Anthropic messages
    authority_gate: stable protocol routes import response shapers from the
      explicit protocol module; the broad model-mounting facade no longer
      exposes compatibility helpers as ambient API surface
    execution_backend: response shaping remains a JS protocol facade while the
      underlying invocation/admission/receipt path remains Rust-admitted; this
      slice removes the legacy re-export, not the protocol route itself
    truth_path: no meaningful transition is admitted through the protocol
      helper export; accepted truth still flows through model_mount admission,
      receipt_binder, and Agentgres before the response helper serializes public
      output
    projection_path: projections and protocol responses continue reading the
      same accepted invocation result, but callers must use the stable
      `model-mounting/protocol-responses.mjs` module rather than the broad
      model-mounting compatibility facade
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/openai-compat-routes.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/protocol-responses.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - OpenAI-compatible route handlers import protocol response helpers from
      the explicit protocol module
    - `model-mounting.mjs` no longer re-exports protocol response helpers
    - protocol response tests assert the broad facade does not expose
      `openAiChatCompletion`, `openAiResponse`, `openAiEmbedding`,
      `openAiCompletion`, or `anthropicMessage`
    - bridge conformance detects the retired facade re-export
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/protocol-responses.test.mjs
      - node -e "import('./packages/runtime-daemon/src/openai-compat-routes.mjs')"
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - concrete non-fixture provider request/response transport still runs in
        JS as Rust-admitted observations until moved behind Rust
        workload_client/model_mount execution ownership
      - protocol response shaping still runs in JS as a stable protocol facade,
        but no longer through the broad model-mounting compatibility re-export
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 42

```yaml
ImplementationSlice:
  objective: retire provider compatibility translation markers from accepted
    model invocation receipts and native protocol responses
  owner_boundary:
    route_or_surface: non-stream provider results, native stream-start provider
      results, accepted model invocation receipt details, and native invocation
      protocol responses
    authority_gate: provider results that attempt to declare
      `compatTranslation` or `compat_translation` now fail closed before Rust
      provider-result admission, invocation receipt binding, Agentgres
      admission, or native response serialization
    execution_backend: concrete non-fixture provider transport still runs in JS
      during migration, but it cannot surface compatibility-translation markers
      as admitted result semantics
    truth_path: accepted receipts no longer carry `compatTranslation`, and a
      translated provider result cannot become an admitted provider-result
      observation
    projection_path: projections and protocol responses continue to serialize
      admitted invocation truth without a compatibility-translation field
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/openai-compat-routes.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - non-stream provider results with `compatTranslation` fail closed before
      provider-result admission
    - stream-start provider results with `compatTranslation` fail closed before
      provider-result admission
    - accepted model invocation receipts do not carry `compatTranslation`
    - native invocation responses do not emit `compat_translation`
    - bridge conformance detects retired compatibility-translation receipt
      plumbing
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - concrete non-fixture provider request/response transport still runs in
        JS as Rust-admitted observations until moved behind Rust
        workload_client/model_mount execution ownership
      - protocol response shaping still runs in JS as a stable protocol facade
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 43

```yaml
ImplementationSlice:
  objective: migrate native-local non-stream model provider invocation through
    Rust model_mount and retire fixture-only provider-invocation bridge naming
  owner_boundary:
    route_or_surface: fixture/local-folder provider invocation, plus native-local
      non-stream provider invocation selected by `ioi_native_local`,
      `ioi_native`, or `native_local`
    authority_gate: provider calls still require Rust provider-execution
      admission first; migrated provider invocations now use the shared
      `execute_model_mount_provider_invocation` bridge operation tied to the
      admitted provider-execution ref/hash
    execution_backend: `rust_model_mount_fixture` remains the fixture/local
      backend; `rust_model_mount_native_local` now computes deterministic
      native-local non-stream responses, backend ids, evidence refs, token
      envelopes, and invocation hashes in Rust model_mount
    truth_path: accepted model invocation receipts carry Rust provider-execution
      refs plus Rust provider-invocation evidence before invocation admission,
      receipt_binder binding, accepted_receipt_append, and Agentgres admission
    projection_path: model-mounting projections continue reading accepted
      receipts; native-local non-stream invocations now expose
      `rust_model_mount.native_local` evidence for replay/inspection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
      - Rust model_mount unit tests in crates/services/src/agentic/runtime/kernel/model_mount.rs
      - Rust bridge unit tests in crates/node/src/bin/ioi_step_module_bridge/mod.rs
  conformance_checks:
    - Rust model_mount provider invocation accepts fixture/local and
      native-local non-stream execution backends, and still rejects unmigrated
      or streaming provider-invocation backends
    - Rust bridge exposes and tests `execute_model_mount_provider_invocation`
      for both fixture and native-local non-stream provider invocations
    - daemon non-stream native-local invocation fails closed before the JS
      provider driver call when Rust provider-invocation execution is
      unavailable
    - daemon native-local streams continue through the existing stream transport
      only as Rust-admitted stream-start observations
    - conformance bridge and receipts tiers detect the shared provider
      invocation bridge, native-local Rust backend, and retired fixture-only
      command name
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - cargo test -p ioi-node ioi_step_module_bridge
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response transports still run in JS as Rust-admitted
        observations until migrated behind Rust workload_client/model_mount
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 44

```yaml
ImplementationSlice:
  objective: retire JS direct non-stream invoke shims for migrated local model
    providers
  owner_boundary:
    route_or_surface: `FixtureModelProviderDriver.invoke` and
      `NativeLocalModelProviderDriver.invoke`
    authority_gate: local fixture and native-local non-stream provider
      invocations are Rust model_mount provider-invocation work once
      provider-execution admission has accepted the boundary
    execution_backend: JS local provider drivers keep health/list/load/unload
      and the still-migrating native stream transport, but their direct
      non-stream `invoke()` methods now fail closed with
      `model_mount_local_provider_direct_invoke_retired`
    truth_path: no accepted local non-stream provider output can be produced by
      a direct JS local provider invoke shim; accepted output must enter through
      Rust provider invocation, invocation admission, receipt_binder, and
      Agentgres admission
    projection_path: unchanged; projections continue reading accepted model
      invocation receipts and Rust provider-invocation evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - local provider driver direct non-stream `invoke()` methods expose the
      retired-path fail-closed code
    - JS local provider drivers no longer import `deterministicOutput` for
      direct fixture output
    - JS local provider drivers no longer log direct `model_invoke` /
      `invoke` events for local non-stream provider execution
    - native-local streaming remains covered by the existing stream lifecycle
      tests until the stream backend is migrated behind Rust
  verification:
    commands:
      - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - native stream byte transport and stream frame production still run in JS
        until concrete provider stream backends move behind Rust
        workload_client/model_mount execution ownership
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response transports still run in JS as Rust-admitted
        observations until migrated behind Rust workload_client/model_mount
      - local provider health/list/load/unload remain JS daemon control
        surfaces while execution ownership is moved route by route
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 45

```yaml
ImplementationSlice:
  objective: move native-local stream frame planning and JSONL chunk production
    into Rust model_mount
  owner_boundary:
    route_or_surface: native-local provider stream invocation selected by
      `ioi_native_local`, `native_local`, or `ioi_native`
    authority_gate: stream invocation only runs after Rust provider-execution
      admission records `stream_status: started`; direct JS native-local stream
      production now fails closed with
      `model_mount_local_provider_direct_stream_retired`
    execution_backend: Rust `model_mount` owns native-local stream output text,
      token count, stream format/kind, chunks, evidence refs, and invocation
      hash; JS only adapts returned chunks into the daemon protocol
      `ReadableStream`
    truth_path: stream-start model invocation receipts still pass through Rust
      invocation admission, provider-result admission, receipt_binder, and
      Agentgres admission before JS store persistence
    projection_path: unchanged; projections continue reading accepted model
      invocation receipts and Rust stream invocation/provider-result evidence
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust model_mount exposes a provider stream invocation schema/result and
      rejects unstarted or non-native-local stream backends
    - daemon stream start calls
      `execute_model_mount_provider_stream_invocation` for native-local streams
      instead of `NativeLocalModelProviderDriver.streamInvoke`
    - JS local provider drivers no longer contain direct native-local stream
      frame/chunk production helpers
    - returned Rust chunks are adapted only into a protocol stream facade before
      provider-result admission and accepted receipt binding
    - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM streams
      remain JS provider observations until their concrete transports migrate
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - cargo test -p ioi-node ioi_step_module_bridge
      - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS still adapts Rust native-local JSONL chunks into a daemon protocol
        stream facade; it does not plan the stream frames
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - local provider health/list/load/unload remain JS daemon control
        surfaces while execution ownership is moved route by route
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 46

```yaml
ImplementationSlice:
  objective: remove dead JS native-local stream framing helpers after Rust
    stream invocation owns chunk planning
  owner_boundary:
    route_or_surface: `native-local-fixture.mjs` stream helper exports
    authority_gate: unchanged; native-local stream invocation remains gated by
      Rust provider-execution admission and
      `execute_model_mount_provider_stream_invocation`
    execution_backend: Rust `model_mount` remains the only native-local stream
      frame/chunk planner; JS fixture output helpers no longer expose
      stream-record, JSONL-stream, or frame-delay utilities
    truth_path: no accepted transition is added; this deletes dead compatibility
      code left behind after Slice 45
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/native-local-fixture.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `native-local-fixture.mjs` no longer exports
      `nativeLocalStreamRecords`, `jsonLineReadableStream`, or
      `providerStreamFrameDelayMs`
    - the bridge conformance tier guards both the local provider driver and
      native-local fixture module against reintroducing JS stream-framing
      helpers
    - native-local deterministic non-stream fixture tests remain in place
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs packages/runtime-daemon/src/model-mounting/native-local-fixture.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/native-local-fixture.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS still adapts Rust native-local JSONL chunks into a daemon protocol
        stream facade; it does not plan the stream frames
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - local provider health/list/load/unload remain JS daemon control
        surfaces while execution ownership is moved route by route
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 47

```yaml
ImplementationSlice:
  objective: delete the obsolete JS native-local output fixture wrapper after
    Rust model_mount owns native-local provider output
  owner_boundary:
    route_or_surface: `native-local-fixture.mjs` and its self-test
    authority_gate: unchanged; native-local non-stream and stream provider
      output remain admitted through Rust provider-execution plus Rust provider
      invocation/stream invocation
    execution_backend: Rust `model_mount` is the canonical deterministic
      native-local provider output source for admitted invocations; the old JS
      wrapper no longer exists as a compatibility surface
    truth_path: no accepted transition is added; this removes dead test-only JS
      output fixture code left behind by the native-local migration
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/native-local-fixture.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `native-local-fixture.mjs` and `native-local-fixture.test.mjs` are absent
    - bridge conformance fails if the retired JS native-local fixture wrapper or
      its stream helper API reappears
    - model-mounting tests still pass through Rust native-local invocation and
      stream invocation paths
  verification:
    commands:
      - node --check scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS still adapts Rust native-local JSONL chunks into a daemon protocol
        stream facade; it does not plan the stream frames
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - local provider health/list/load/unload remain JS daemon control
        surfaces while execution ownership is moved route by route
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 48

```yaml
ImplementationSlice:
  objective: delete retired JS native fixture response modules after
    native-local output moved to Rust model_mount
  owner_boundary:
    route_or_surface: old `native-fixture-*` JS prompt/response scaffolding and
      its stage-78 proof generator
    authority_gate: unchanged; native-local provider output remains admitted
      through Rust provider-execution plus Rust provider invocation/stream
      invocation
    execution_backend: Rust `model_mount` remains the canonical deterministic
      native-local provider output source for admitted invocations; no JS
      fixture-response module remains as a hidden output backend
    truth_path: no accepted transition is added; this removes test-only legacy
      scaffolding that no longer has a production import path
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/native-fixture-artifacts.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-intent.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-tool-catalogue.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/native-fixture-intent.test.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.test.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.test.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.test.mjs
      - packages/runtime-daemon/src/model-mounting/native-fixture-tool-catalogue.test.mjs
      - scripts/lib/workflow-native-fixture-intent-refactor-proof.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance fails if any retired JS native fixture response module
      or its old proof generator reappears
    - model-mounting tests still pass through Rust native-local invocation and
      stream invocation paths
    - live native fixture model/provider records remain in default records and
      state seeding; only the obsolete JS response backend is removed
  verification:
    commands:
      - node --check scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS still adapts Rust native-local JSONL chunks into a daemon protocol
        stream facade; it does not plan the stream frames
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - local provider health/list/load/unload remain JS daemon control
        surfaces while execution ownership is moved route by route
      - the JS store still writes the projection/cache receipt envelope after
        Rust admission; broader operation-log ownership remains to be moved to
        Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 49

```yaml
ImplementationSlice:
  objective: route native-local provider load/unload lifecycle result envelopes
    through Rust model_mount
  owner_boundary:
    route_or_surface: native-local provider lifecycle control surface
      (`NativeLocalModelProviderDriver.load` and `.unload`)
    authority_gate: unchanged; this slice plans lifecycle result envelopes after
      daemon process supervision and before JS state persistence
    execution_backend: Rust `model_mount` owns the native-local lifecycle
      status/backend/driver/evidence envelope through
      `rust_model_mount_native_local_lifecycle`; JS continues to supervise
      backend processes and write backend logs until the process-control
      boundary migrates
    truth_path: unchanged; model instance persistence and lifecycle receipts
      still write through the JS daemon state surface after the Rust-planned
      lifecycle envelope
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires `plan_model_mount_provider_lifecycle`
      through `ModelMountProviderLifecycleRequest`
    - receipts conformance requires Rust `model_mount` lifecycle schema,
      unsupported-backend/action guards, evidence refs, hash planning, and
      kernel-service facade
    - native-local driver tests assert load/unload call
      `state.planModelMountProviderLifecycle`
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - node --check packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs packages/runtime-daemon/src/model-mounting.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - cargo test -p ioi-node ioi_step_module_bridge
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan the lifecycle result envelope
      - JS still persists model instance state and lifecycle receipts after the
        Rust-planned lifecycle envelope
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - local provider health/list surfaces remain JS daemon control surfaces
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 50

```yaml
ImplementationSlice:
  objective: route native-local provider health result envelopes through Rust
    model_mount
  owner_boundary:
    route_or_surface: native-local provider health control surface
      (`NativeLocalModelProviderDriver.health`)
    authority_gate: unchanged; provider health remains a daemon-observed
      control surface while its public status/evidence envelope is planned by
      Rust
    execution_backend: Rust `model_mount` lifecycle planner now owns
      native-local health/load/unload status, backend, evidence, and hash
      envelopes through `rust_model_mount_native_local_lifecycle`
    truth_path: unchanged; provider health persistence and receipts still write
      through the JS daemon state surface after the Rust-planned health envelope
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires native-local health/load/unload lifecycle
      envelopes to use the Rust planner and provider status binding
    - receipts conformance continues to require Rust lifecycle schema,
      unsupported-backend/action guards, evidence refs, hash planning, and
      kernel-service facade
    - native-local driver tests assert configured and blocked health call the
      Rust lifecycle planner
  verification:
    commands:
      - cargo fmt -p ioi-services
      - node --check packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still calls the native-local health method and persists provider
        health receipts after the Rust-planned envelope
      - local provider model/list-loaded surfaces remain JS daemon control
        surfaces
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 51

```yaml
ImplementationSlice:
  objective: route fixture provider health/load/unload lifecycle envelopes
    through Rust model_mount
  owner_boundary:
    route_or_surface: fixture provider health/load/unload control surface
      (`FixtureModelProviderDriver.health`, `.load`, and `.unload`)
    authority_gate: unchanged; fixture provider lifecycle remains a
      daemon-observed local control surface while its public status/backend/
      evidence envelope is planned by Rust
    execution_backend: Rust `model_mount` lifecycle planner now owns fixture
      and native-local local-provider health/load/unload status, backend,
      driver, evidence, and hash envelopes through
      `rust_model_mount_fixture_lifecycle` and
      `rust_model_mount_native_local_lifecycle`
    truth_path: unchanged; provider and model-instance lifecycle persistence
      still write through the JS daemon state surface after the Rust-planned
      lifecycle envelope
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires fixture and native-local lifecycle envelopes
      to use the Rust planner and fail closed on malformed planner results
    - receipts conformance requires Rust lifecycle schema plus native-local and
      fixture lifecycle backend recognition
    - local provider driver tests assert fixture health/load/unload call the
      Rust lifecycle planner
  verification:
    commands:
      - cargo fmt -p ioi-services
      - node --check packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still calls local provider lifecycle methods and persists
        provider/model-instance lifecycle receipts after Rust-planned envelopes
      - local provider model/list-loaded surfaces remain JS daemon control
        surfaces
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 52

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-52
  phase: 4
  objective: move local provider model/list-loaded inventory result envelopes
    into Rust model_mount
  owner_boundary:
    route_or_surface: fixture and native-local local provider model/list-loaded
      surfaces (`listModels` and `listLoaded`)
    authority_gate: unchanged; JS still reads daemon state records, but the
      public inventory status/backend/evidence/hash envelope must be planned
      by Rust before records are returned
    execution_backend: Rust `model_mount` provider-inventory planner now owns
      fixture and native-local local-provider list_models/list_loaded status,
      backend, driver, item refs, evidence, and hash envelopes through
      `rust_model_mount_fixture_inventory` and
      `rust_model_mount_native_local_inventory`
    truth_path: unchanged; model artifacts and model instances still read from
      the JS daemon state surface until broader Agentgres-backed store demotion
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires fixture and native-local listModels/listLoaded
      envelopes to use the Rust inventory planner and fail closed on malformed
      planner results
    - receipts conformance requires Rust inventory schema plus native-local and
      fixture inventory backend recognition
    - local provider driver tests assert fixture/native-local model and loaded
      inventory calls the Rust planner
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - node --check packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs packages/runtime-daemon/src/model-mounting.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - cargo test -p ioi-node ioi_step_module_bridge
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still reads model artifact and model-instance records for local
        provider list surfaces before Rust plans the returned inventory envelope
      - JS still calls local provider lifecycle methods and persists
        provider/model-instance lifecycle receipts after Rust-planned envelopes
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response and stream transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 53

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-53
  phase: 4
  objective: bind migrated local provider model-instance load/unload
    transitions to Rust model_mount
  owner_boundary:
    route_or_surface: model instance state transition for migrated local
      provider `loadModel` and `unloadModel`
    authority_gate: unchanged; JS still writes the model-instance map, but
      migrated local provider load/unload transitions must obtain a Rust
      instance lifecycle status/evidence/hash result before persistence
    execution_backend: Rust `model_mount` instance-lifecycle planner owns
      load/unload target status validation, backend/driver binding,
      provider-lifecycle hash binding, evidence, and transition hash through
      `rust_model_mount_instance_lifecycle`
    truth_path: unchanged; model-instance records and lifecycle receipts still
      persist through the JS daemon state surface after Rust transition
      planning
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires migrated local provider model load/unload
      instance transitions to use the Rust instance lifecycle planner and fail
      closed before JS state writes on malformed planner results
    - receipts conformance requires Rust instance lifecycle schema, backend
      recognition, action/status guards, and provider lifecycle hash binding
    - model-loading tests assert load/unload records and lifecycle receipts
      carry the Rust instance lifecycle hash
  verification:
    commands:
      - cargo fmt -p ioi-services -p ioi-node
      - node --check packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs packages/runtime-daemon/src/model-mounting.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - cargo test -p ioi-services agentic::runtime::kernel::model_mount
      - cargo test -p ioi-node ioi_step_module_bridge
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still writes model-instance maps and lifecycle receipts after Rust
        plans migrated local provider instance transitions
      - JS still reads model artifact and model-instance records for local
        provider list surfaces before Rust plans the returned inventory envelope
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 54

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-54
  phase: 5
  objective: fail closed on direct migrated local-provider model-instance
    persistence without Rust lifecycle binding
  owner_boundary:
    route_or_surface: `model-instances` map persistence for migrated local
      provider records
    authority_gate: unchanged; JS still delegates map persistence to the
      daemon store, but migrated local-provider loaded/unloaded/evicted/
      superseded instance records must carry Rust instance lifecycle binding
      evidence before write
    execution_backend: unchanged; Rust `model_mount` instance-lifecycle
      planner remains the owner of provider-lifecycle hash binding and
      transition hashes
    truth_path: JS persistence surface now fails closed when migrated
      local-provider instance records lack Rust `model_mount`
      `rust_model_mount_instance_lifecycle` evidence and hashes
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/state-persistence.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance requires direct migrated local-provider
      model-instance map writes to fail closed without Rust instance lifecycle
      hashes and evidence
    - state persistence tests assert malformed local-provider instance records
      are rejected while Rust-bound local and non-migrated provider records
      still persist
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/state-persistence.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still writes model-instance maps and lifecycle receipts after Rust
        plans migrated local provider instance transitions, but direct writes
        for migrated local provider instances now require Rust lifecycle hashes
      - JS still reads model artifact and model-instance records for local
        provider list surfaces before Rust plans the returned inventory envelope
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 55

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-55
  phase: 5
  objective: bind migrated local-provider model-instance evict/supersede
    lifecycle transitions and lifecycle receipts to the Rust action/status
    contract
  owner_boundary:
    route_or_surface: migrated local provider `model-instances` lifecycle
      transitions for load, unload, idle eviction, and supersede
    authority_gate: unchanged; JS may still trigger state persistence, but
      migrated local-provider lifecycle records and receipts must carry Rust
      instance lifecycle action/status/hash evidence before persistence
    execution_backend: Rust `model_mount` instance-lifecycle planner validates
      canonical action/status pairs for load/loaded, unload/unloaded,
      evict/evicted, and supersede/superseded
    truth_path: JS direct map and lifecycle receipt persistence fail closed when
      migrated local-provider instance records lack matching Rust action/status,
      lifecycle hash, provider lifecycle hash, and evidence refs
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs
      - packages/runtime-daemon/src/model-mounting/loaded-instances.mjs
      - packages/runtime-daemon/src/model-mounting/state-persistence.mjs
      - packages/runtime-daemon/src/model-mounting/receipt-operations.mjs
      - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/model_mount.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs
      - packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs
      - packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - bridge conformance requires migrated local provider load/unload/evict/
      supersede instance lifecycle transitions to be planned through Rust
      `model_mount`
    - receipts conformance requires direct migrated local-provider
      model-instance map writes and lifecycle receipt writes to fail closed
      without matching Rust action/status/hash/evidence binding
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.mjs packages/runtime-daemon/src/model-mounting/state-persistence.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
      - cargo test -p ioi-services model_instance
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still writes model-instance maps and lifecycle receipts after Rust
        plans migrated local provider instance transitions, but direct writes
        and receipts for migrated local provider instances now require Rust
        action/status hashes and evidence
      - JS still reads model artifact and model-instance records for local
        provider list surfaces before Rust plans the returned inventory envelope
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 56

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-56
  phase: 5
  objective: fail closed on direct migrated local-provider lifecycle receipt
    store writes without provider kind and Rust instance lifecycle binding
  owner_boundary:
    route_or_surface: direct `model_lifecycle` receipt persistence for migrated
      local provider model-instance load/unload/evict/supersede transitions
    authority_gate: unchanged; JS receipt helper and direct store writes are
      both non-authoritative unless provider kind and Rust instance lifecycle
      binding are present
    execution_backend: unchanged; Rust `model_mount` instance-lifecycle planner
      remains the source of canonical action/status/hash/evidence
    truth_path: direct store writes for migrated local-provider lifecycle
      receipts now fail closed before receipt persistence and operation append
      when provider kind or Rust binding is missing
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs
      - packages/runtime-daemon/src/model-mounting/loaded-instances.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance requires model lifecycle receipt helpers to include
      provider kind for model-instance lifecycle operations
    - receipts conformance requires direct store writes for migrated local
      provider model lifecycle receipts to fail closed without provider kind
      and Rust action/status/hash/evidence binding
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still persists lifecycle receipts after Rust plans migrated local
        provider instance transitions, but direct helper and store writes now
        require provider kind plus Rust action/status/hash/evidence binding
      - JS still writes model-instance maps after Rust plans migrated local
        provider instance transitions
      - JS still reads model artifact and model-instance records for local
        provider list surfaces before Rust plans the returned inventory envelope
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 57

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-57
  phase: 5
  objective: bind migrated local-provider inventory lifecycle receipts to Rust
    provider inventory hashes
  owner_boundary:
    route_or_surface: provider `listModels` and `listLoaded` lifecycle receipts
      for fixture and native-local providers
    authority_gate: unchanged; provider list route helpers may still render JS
      arrays, but migrated local-provider inventory receipts must carry provider
      kind plus Rust inventory action/status/hash/evidence before persistence
    execution_backend: unchanged; Rust `model_mount` provider-inventory planner
      remains the source of list_models/list_loaded hashes and evidence
    truth_path: direct store writes for migrated local-provider provider
      inventory receipts now fail closed before receipt persistence and
      operation append when provider kind or Rust inventory binding is missing
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
      - packages/runtime-daemon/src/model-mounting/provider-operations.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance requires local provider list route receipts to carry
      Rust provider inventory action/status/hash/evidence binding
    - receipts conformance requires direct store writes for migrated local
      provider inventory lifecycle receipts to fail closed without provider kind
      and Rust inventory binding
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/provider-operations.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still reads local provider model artifact and model-instance records
        before Rust plans returned inventory envelopes, but route receipts and
        direct store appends now require Rust inventory hashes/evidence
      - JS still writes model-instance maps and lifecycle receipts after Rust
        plans migrated local provider instance transitions
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 58

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-58
  phase: 5
  objective: bind migrated local-provider health receipts to Rust provider
    lifecycle hashes
  owner_boundary:
    route_or_surface: `provider_health` receipts for fixture and native-local
      provider health checks
    authority_gate: unchanged; provider health routes may still render JS public
      provider projections, but migrated local-provider health receipts must
      carry provider kind plus Rust lifecycle action/status/hash/evidence before
      persistence
    execution_backend: unchanged; Rust `model_mount` provider-lifecycle planner
      remains the source of health status hashes and evidence
    truth_path: direct store writes for migrated local-provider `provider_health`
      receipts now fail closed before receipt persistence and operation append
      when provider kind or Rust lifecycle binding is missing
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
      - packages/runtime-daemon/src/model-mounting/provider-operations.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance requires local provider health route receipts to
      carry Rust provider lifecycle action/status/hash/evidence binding
    - receipts conformance requires direct store writes for migrated local
      provider health receipts to fail closed without provider kind and Rust
      lifecycle binding
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/provider-operations.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still renders provider health projections after Rust plans the health
        lifecycle envelope, but direct provider-health receipt appends now
        require Rust lifecycle hashes/evidence for migrated local providers
      - JS still reads local provider model artifact and model-instance records
        before Rust plans returned inventory envelopes, but route receipts and
        direct store appends now require Rust inventory hashes/evidence
      - JS still writes model-instance maps and lifecycle receipts after Rust
        plans migrated local provider instance transitions
      - JS still performs native-local backend process supervision and backend
        log writes before asking Rust to plan load/unload lifecycle result
        envelopes
      - hosted/openai-compatible, Ollama, LM Studio, llama.cpp, and vLLM
        request/response, stream, and load/unload transports still run in JS as
        Rust-admitted observations until migrated behind Rust
        workload_client/model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 59

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-59
  phase: 11
  objective: retire migrated local-provider JS-only start/stop lifecycle control
    shims
  owner_boundary:
    route_or_surface: `provider_start` and `provider_stop` lifecycle receipts
      for fixture and native-local providers
    authority_gate: unchanged; non-migrated provider start/stop can still record
      stateless lifecycle observations, but migrated local provider start/stop
      must fail closed unless a Rust `model_mount` lifecycle binding exists
    execution_backend: unchanged; Rust `model_mount` provider lifecycle
      currently owns health/load/unload, so local start/stop is not admitted as
      a JS-only compatibility path
    truth_path: direct store writes for migrated local-provider provider
      start/stop lifecycle receipts now fail closed before receipt persistence
      and operation append when provider kind or Rust lifecycle binding is
      missing
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-operations.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance requires migrated local-provider start/stop to fail
      closed without Rust lifecycle planning
    - receipts conformance requires direct store writes for migrated local
      provider start/stop lifecycle receipts to fail closed without provider
      kind and Rust lifecycle binding
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/provider-operations.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - non-migrated provider start/stop can still emit stateless observations
        until those provider transports move behind Rust workload/model_mount
        execution ownership
      - Rust `model_mount` provider lifecycle does not yet implement local
        start/stop as admitted actions; the migrated local JS-only path now
        fails closed instead of preserving compatibility behavior
      - JS still renders provider health projections after Rust plans the health
        lifecycle envelope
      - JS still reads local provider model artifact and model-instance records
        before Rust plans returned inventory envelopes
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 60

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-60
  phase: 11
  objective: extract model-mounting receipt write guards from the JS store
    adapter
  owner_boundary:
    route_or_surface: model-mounting receipt persistence policy
    authority_gate: unchanged; the same direct-write guards remain enforced
      before receipt persistence and operation append
    execution_backend: unchanged
    truth_path: unchanged; `AgentgresModelMountingStore.writeReceipt` now
      delegates receipt admission policy to
      `model-mounting/receipt-write-guards.mjs`
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/store.mjs
      - packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - receipts conformance still requires the invocation, model lifecycle,
      provider inventory, provider health, and provider control direct-write
      guards
    - receipts conformance now requires the store adapter to call the extracted
      receipt-write guard module instead of owning guard internals
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - behavior is unchanged; this slice only separates store persistence from
        receipt admission policy so future guard migration can move toward Rust
        Agentgres admission without re-growing the JS store adapter
      - broader JS store demotion remains pending
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 61

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-61
  phase: 11
  objective: retire provider-open retry operation-like append from provider
    transport
  owner_boundary:
    route_or_surface: model-mounting provider transport retry handling
    authority_gate: unchanged; provider retry remains a transport retry delay,
      not an admitted state transition
    execution_backend: unchanged
    truth_path: unchanged; the removed `model.provider_open_retry` append was
      trace noise and is not replaced with another accepted receipt or
      operation path
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting/provider-transport.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - provider transport no longer contains the `model.provider_open_retry`
      operation-like append
    - provider transport retry behavior still retries transient provider
      readiness failures without appending operation-like records
    - receipts conformance detects the retired append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting/provider-transport.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - broader provider transport execution and provider state projection still
        remain in JS until each backend moves behind Rust workload_client and
        model_mount execution ownership
      - broader operation-log ownership remains to be moved to Rust Agentgres
        admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 62

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-62
  phase: 11
  objective: retire wallet authority local audit operation-like append
  owner_boundary:
    route_or_surface: model-mounting wallet authority audit mirroring
    authority_gate: unchanged; capability grants, revocation, and scope checks
      still execute through the wallet authority adapter and wallet.network
      remote boundary mirror
    execution_backend: unchanged
    truth_path: capability-token and vault-ref receipts remain the local
      admitted truth path; wallet audit mirroring no longer appends `wallet.*`
      operation-like records directly through daemon JS
    projection_path: unchanged; authority snapshots continue reading tokens,
      vault refs, and admitted receipts
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/wallet-authority.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - wallet authority source no longer references `appendOperation`
    - wallet authority grant, authorize, revoke, and vault-ref resolution tests
      prove no local operation-like records are appended
    - receipts conformance detects the retired wallet audit append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting.mjs packages/runtime-daemon/src/model-mounting/wallet-authority.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - the wallet authority adapter is still JS and only mirrors remote
        wallet.network audit events; full wallet.network grant/approval
        protocol ownership remains pending
      - vault audit appends and broader JS store operation append surfaces
        still remain to be retired or moved behind Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 63

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-63
  phase: 11
  objective: retire vault port local audit operation-like append
  owner_boundary:
    route_or_surface: model-mounting vault port audit mirroring
    authority_gate: unchanged; vault refs still enforce wallet.network-style
      `vault://` boundaries and never persist plaintext material
    execution_backend: unchanged
    truth_path: vault-ref binding, removal, and adapter-health receipts remain
      the local admitted truth path; vault audit mirroring no longer appends
      `vault.*` operation-like records directly through daemon JS
    projection_path: unchanged; authority and model-mounting projections
      continue reading vault metadata and admitted receipts
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/vault-port.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/vault-port.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - vault port source no longer references `appendOperation`
    - vault port resolve, bind, and remove tests prove no local operation-like
      records are appended
    - receipts conformance detects the retired vault audit append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting.mjs packages/runtime-daemon/src/model-mounting/vault-port.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/vault-port.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - vault material custody and metadata persistence remain JS-managed until
        the cTEE/private-workspace and wallet.network vault paths move behind
        Rust-owned custody/admission
      - broader JS store operation append surfaces still remain to be retired
        or moved behind Rust Agentgres admission
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 64

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-64
  phase: 5
  objective: retire model-mounting store receipt operation-log append and derive
    local heads from receipts
  owner_boundary:
    route_or_surface: model-mounting receipt persistence and projection
      watermarking
    authority_gate: unchanged; receipt writes still pass the extracted
      receipt-write guards before persistence
    execution_backend: unchanged
    truth_path: receipt files remain the local projection/cache persistence
      path after Rust receipt_binder and Agentgres admission; the store no
      longer appends duplicate daemon JS operation-log records for persisted
      receipts
    projection_path: model-mounting local head and projection watermark now
      derive from persisted receipt count instead of daemon-local
      `operation-log.jsonl`
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/store.mjs
      - packages/runtime-daemon/src/model-mounting/projections.mjs
      - packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/model-mounting/store.test.mjs
      - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
      - packages/runtime-daemon/src/model-mounting/projections.test.mjs
      - packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - model-mounting store source no longer references `appendOperation`
    - store tests prove receipt files persist after Rust binding/admission
      without appending operation-log records
    - model-mounting local head and projection watermark derive from
      `listReceipts().length`
    - receipts conformance detects the retired store operation append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/model-mounting.mjs packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/projections.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - the JS store still persists receipt/projection cache files after Rust
        binding/admission; broader store ownership remains to move behind Rust
        Agentgres admission
      - non-model-mounting daemon operation-log append surfaces remain outside
        this slice
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 65

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-65
  phase: 5
  objective: retire OpenAI provider stream-shape operation-like append
  owner_boundary:
    route_or_surface: OpenAI-compatible native provider chat stream facade
    authority_gate: unchanged; stream start still passes model-mounting
      authorization and provider-result admission before bytes are forwarded
    execution_backend: unchanged; native provider stream transport remains a
      non-migrated facade over an admitted provider stream-start observation
    truth_path: stream-shape evidence is bound into the
      `model_invocation_stream_completed` receipt after Rust receipt_binder and
      Agentgres admission instead of being appended as a duplicate daemon JS
      operation-like record
    projection_path: unchanged; protocol responses and projections read the
      admitted receipt details
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/openai-compat-routes.mjs
      - packages/runtime-daemon/src/model-mounting.mjs
      - packages/runtime-daemon/src/model-mounting/conversation-operations.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/openai-compat-routes.test.mjs
      - packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - OpenAI-compatible route no longer appends
      `model.provider_stream_shape_summary`
    - native provider stream test proves stream-shape evidence is passed to the
      stream-completion receipt without local operation append
    - stream-completion receipt test proves `providerStreamShapeSummary`
      persists through receipt details
    - receipts conformance detects the retired stream-shape append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/openai-compat-routes.mjs packages/runtime-daemon/src/openai-compat-routes.test.mjs packages/runtime-daemon/src/model-mounting.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/openai-compat-routes.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
      - npm run hypervisor-conformance:receipts
      - node --test packages/runtime-daemon/src/model-mounting/*.test.mjs packages/runtime-daemon/src/openai-compat-routes.test.mjs
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - native OpenAI-compatible stream forwarding remains JS facade code until
        the hosted/non-migrated stream transport moves behind Rust
        workload_client/model_mount execution
      - non-model-mounting daemon operation-log append surfaces remain outside
        this slice
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 66

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-66
  phase: 11
  objective: retire stale ModelMountingState appendOperation injection
  owner_boundary:
    route_or_surface: runtime daemon store to model-mounting state constructor
    authority_gate: unchanged; model-mounting transitions still use the
      existing authority, receipt-write guard, receipt_binder, and Agentgres
      admission paths
    execution_backend: unchanged
    truth_path: no daemon-local operation append callback is injected into the
      model-mounting state facade after model-mounting receipt/admission paths
      have been migrated away from operation-log mirroring
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/index.mjs
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - runtime daemon constructor wiring no longer passes `appendOperation` into
      `ModelMountingState`
    - receipts conformance detects reintroduced model-mounting append callback
      injection
  verification:
    commands:
      - node --check packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - memory and thread runtime surfaces still own separate daemon-local
        operation-log append paths outside this model-mounting cleanup
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 67

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-67
  phase: 5
  objective: retire AgentMemoryStore operation-log mirroring
  owner_boundary:
    route_or_surface: daemon agent memory record and policy persistence
    authority_gate: unchanged; existing memory policy/read-only/write-approval
      gates still decide whether memory mutations may occur
    execution_backend: unchanged
    truth_path: memory record and policy files remain the local persistence
      surface for this slice, while the duplicate daemon-local `memory.*`
      operation-log mirror is removed
    projection_path: unchanged; memory projections read record and policy files
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/memory-store.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/memory-store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - memory store source no longer references `appendOperation`
    - daemon store constructs `AgentMemoryStore` without an append callback
    - memory store test proves record write, edit, delete, and policy update
      persistence without local operation append
    - receipts conformance detects the retired memory operation append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/memory-store.mjs packages/runtime-daemon/src/memory-store.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/memory-store.test.mjs packages/runtime-daemon/src/threads/thread-memory-state.test.mjs packages/runtime-daemon/src/runtime-memory-helpers.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - memory record/policy files are still JS-managed local persistence until
        the memory route family receives Rust Agentgres admission and projection
        ownership
      - thread persistence and runtime-bridge surfaces still append daemon-local
        operation-log records outside this slice
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 68

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-68
  phase: 5
  objective: retire runtime-bridge turn budget/error operation mirrors
  owner_boundary:
    route_or_surface: runtime bridge thread turn submission
    authority_gate: unchanged; runtime bridge availability, request shaping, and
      bridge unavailable fail-closed mapping still happen before turn projection
      return
    execution_backend: unchanged; runtime bridge still executes the turn
    truth_path: submitted turns still persist through `writeRun` and runtime
      event projections; duplicate `turn.runtime_bridge.submit_budget` and
      `turn.runtime_bridge.submit_error` daemon-local operation mirrors are
      removed
    projection_path: unchanged; turn projections and runtime events remain the
      user/API read path
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - runtime bridge turn source no longer appends submit budget/error operation
      mirrors
    - runtime bridge tests prove successful and failed turn submits do not append
      extra daemon-local operation records
    - receipts conformance detects the retired runtime bridge turn append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - thread/agent/run persistence still appends operation-log records until
        those state transitions move behind Rust Agentgres admission
      - runtime read surfaces still expose operation-log counts until the thread
        persistence truth path is migrated
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 69

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-69
  phase: 5
  objective: retire agent delete operation mirror
  owner_boundary:
    route_or_surface: thread store permanent agent deletion
    authority_gate: unchanged; permanent deletion still fails closed when
      canonical runs exist and requires archive/retention review instead
    execution_backend: unchanged
    truth_path: agent deletion mutates the guarded agent map and removes the
      persisted agent record; the duplicate daemon-local `agent.delete`
      operation mirror is removed
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/threads/thread-store.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/threads/thread-store.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - thread store source no longer appends `agent.delete`
    - thread store delete test proves guarded deletion removes the agent and
      file without appending a daemon-local operation record
    - receipts conformance detects the retired agent delete append surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/threads/thread-store.mjs packages/runtime-daemon/src/threads/thread-store.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/threads/thread-store.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - agent update/create, subagent persistence, and run persistence still
        append operation-log records until those route-family transitions move
        behind Rust Agentgres admission
      - runtime read surfaces still expose operation-log counts until the thread
        persistence truth path is migrated
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 70

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-70
  phase: 5
  objective: retire agent and subagent persistence operation mirrors
  owner_boundary:
    route_or_surface: thread persistence agent and subagent record writes
    authority_gate: unchanged; caller-owned create/update/spawn authority gates
      still run before persistence
    execution_backend: unchanged
    truth_path: agent and subagent JSON records remain the local persistence
      surface for this slice, while duplicate daemon-local operation-log mirrors
      are removed
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `writeAgentRecord` and `writeSubagentRecord` no longer call
      `store.appendOperation`
    - thread persistence tests prove agent/subagent records are persisted without
      operation entries
    - receipts conformance detects the retired agent/subagent append surfaces
  verification:
    commands:
      - node --check packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - run persistence still appends operation-log records and still drives task
        projection watermarking until the run truth path moves behind Rust
        Agentgres admission
      - operation-log helper/read surfaces remain until the run append is retired
        or replaced by an admitted projection head
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 71

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-71
  phase: 5
  objective: retire run persistence operation-log append and operation-log read
    surfaces
  owner_boundary:
    route_or_surface: thread persistence run record writes plus runtime
      canonical read/doctor/tool/turn projection surfaces
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: unchanged
    truth_path: run, task, job, checklist, receipt, artifact, policy,
      authority, quality, and projection records remain the local state surface
      for this slice; the duplicate daemon-local `operation-log.jsonl` helper,
      append API, count API, and run append are removed
    projection_path: canonical run projection watermarks now derive from the
      run-state projection count and read surfaces advertise
      `agentgres_canonical_state_projection` rather than the retired operation
      log
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/index.mjs
      - packages/runtime-daemon/src/runtime-run-read-surface.mjs
      - packages/runtime-daemon/src/runtime-doctor-report.mjs
      - packages/runtime-daemon/src/runtime-tool-catalog.mjs
      - packages/runtime-daemon/src/threads/thread-turn-projection.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
      - packages/runtime-daemon/src/runtime-doctor-report.test.mjs
      - scripts/lib/live-runtime-daemon-contract.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - thread persistence no longer exports operation-log append/count helpers
      and `writeRunRecord` no longer calls `store.appendOperation`
    - `RuntimeStore` no longer exposes `appendOperation` or `operationCount`
    - canonical run read and doctor surfaces use run-state projection watermarks
      and no longer expose `operation-log.jsonl`
    - the live daemon SDK contract expectation is updated so cancel persistence
      requires the old JS operation log to remain absent when the environment
      can satisfy live model routing
    - receipts conformance detects the retired run operation-log append/read
      surface
  verification:
    commands:
      - node --check packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs packages/runtime-daemon/src/runtime-doctor-report.mjs packages/runtime-daemon/src/runtime-doctor-report.test.mjs packages/runtime-daemon/src/runtime-tool-catalog.mjs packages/runtime-daemon/src/threads/thread-turn-projection.mjs packages/runtime-daemon/src/index.mjs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs packages/runtime-daemon/src/runtime-doctor-report.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable; live SDK cancel/replay
      assertion is updated but direct execution remains gated on a satisfiable
      live model route in this environment
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - run/task/job/checklist/receipt/quality projection records are still
        JS-managed local persistence until run lifecycle transitions receive
        Rust Agentgres admission and projection ownership
      - model-mounting retains its Rust-admitted operation refs and local
        receipt-derived heads until that namespace is fully folded into the
        shared Agentgres core
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 72

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-72
  phase: 5
  objective: require Rust Agentgres run-state transition planning before run
    persistence writes
  owner_boundary:
    route_or_surface: thread persistence run/task/projection state writes
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: unchanged
    truth_path: JS still writes the local run/task/job/checklist/receipt/artifact
      files, but it must first obtain a Rust-planned Agentgres runtime-state
      transition with expected heads, state_root_before, state_root_after,
      resulting_head, projection watermark, receipt refs, and transition hash
    projection_path: task and run projection records now carry the Rust-planned
      `agentgresTransition`; update/cancel writes chain from the previous
      persisted transition head rather than inventing a fresh JS watermark
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust Agentgres admission core exposes and tests
      `RuntimeStateTransitionRequest`
    - command bridge exposes `plan_runtime_run_state_transition`
    - daemon runtime Agentgres runner fails closed without a Rust bridge command
    - run persistence calls Rust transition planning before writing local state
    - run persistence chains update/cancel transitions from the previous
      persisted head/state-root
    - receipts conformance detects the Rust-planned run-state transition
      requirement
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_plans_runtime_run_state_transition_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: update/cancel unit coverage proves the next
      run-state write consumes the prior persisted transition head/state-root
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still performs the local file writes after Rust transition planning;
        the next run lifecycle slices must move accepted operation admission,
        storage ArtifactRef/PayloadRef binding, and projection materialization
        into the Rust daemon core
      - Rust runtime-state transition planning is bridge-command based until the
        extracted Rust daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 73

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-73
  phase: 5
  objective: require Rust storage write admission before canonical runtime
    run-state JSON persistence
  owner_boundary:
    route_or_surface: thread persistence canonical run/task/projection state
      writes
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: unchanged
    truth_path: JS still writes the local JSON records, but canonical run, task,
      and projection writes must first obtain Rust `StorageBackendWriteProposal`
      admission with Agentgres PayloadRef and receipt refs
    projection_path: unchanged from Slice 72; task and projection records carry
      the Rust-planned `agentgresTransition`
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - command bridge exposes `admit_storage_backend_write`
    - daemon runtime Agentgres runner exposes `admitStorageBackendWrite`
    - runtime store exposes `admitRuntimeStateStorageWrite`
    - canonical run, task, and projection JSON writes call Rust storage
      admission before `writeJson`
    - storage admission requests carry content hashes, PayloadRefs, and run
      receipt refs
    - receipts conformance detects the storage-admitted canonical write
      requirement
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_admits_storage_backend_write_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves storage admission events
      are recorded before the canonical run/task/projection JSON writes
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - job, checklist, receipt, artifact, policy, authority, quality, stop,
        scorecard, and ledger sidecar files are still JS local writes; the next
        run-state persistence slices must either extend Rust storage admission
        to those relations or move the writes behind the Rust daemon core
      - storage admission remains command-bridge based until the extracted Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 74

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-74
  phase: 5
  objective: extend Rust storage write admission to every runtime run-state
    sidecar record written by `writeRunRecord`
  owner_boundary:
    route_or_surface: thread persistence run/task/job/checklist/receipt/artifact
      policy/authority/quality/projection state writes
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: unchanged
    truth_path: JS still writes local JSON records, but every `writeRunRecord`
      output must first obtain Rust storage admission with content hash,
      PayloadRef, and run receipt refs
    projection_path: unchanged from Slice 73
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `writeRunRecord` has no raw `writeJson(store.pathFor(...))` calls
    - job, checklist, receipt, artifact, policy, authority, stop-condition,
      scorecard, ledger, and quality records use `writeJsonWithStorageAdmission`
    - unit coverage proves the storage admission count matches the full
      run-state file write count
    - receipts conformance detects the sidecar storage admission requirement
  verification:
    commands:
      - node --check packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves every file path written
      by `writeRunRecord` has a preceding storage admission event
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - run-state persistence still executes as JS local JSON writes after Rust
        transition planning and storage admission; the long-term shape is for
        the extracted Rust daemon core to own those writes in-process
      - storage admission remains command-bridge based until the Rust daemon core
        owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 75

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-75
  phase: 11
  objective: retire the runtime Agentgres admission fallback to model-mount
    command environment variables
  owner_boundary:
    route_or_surface: runtime Agentgres admission command configuration
    authority_gate: unchanged; this slice removes a compatibility alias rather
      than changing admission semantics
    execution_backend: Rust command bridge remains the only configured runtime
      Agentgres backend
    truth_path: unchanged from Slice 74
    projection_path: unchanged from Slice 74
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
    rust_core: []
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - runtime Agentgres admission reads `IOI_RUNTIME_AGENTGRES_COMMAND`
      explicitly
    - runtime Agentgres admission no longer falls back to
      `IOI_MODEL_MOUNT_ADMISSION_COMMAND`
    - unconfigured runtime Agentgres admission still fails closed
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - runtime Agentgres admission is still command-bridge based until the Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 76

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-76
  phase: 10
  objective: move runtime run-state storage content hashing and object-ref
    planning into Rust write-set planning
  owner_boundary:
    route_or_surface: runtime run-state storage write-set planning
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: Rust Agentgres admission command bridge
    truth_path: JS assembles the already-derived record payloads, then Rust
      computes content hashes, object refs, PayloadRefs, storage admissions, and
      the write-set hash before any local JSON write
    projection_path: unchanged from Slice 75
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust Agentgres admission core exposes
      `RuntimeStateStorageWriteSetRequest`
    - command bridge exposes `plan_runtime_state_storage_writes`
    - daemon runtime Agentgres runner exposes `planRuntimeStateStorageWrites`
    - runtime store exposes `planRuntimeStateStorageWrites`
    - `writeRunRecord` plans the complete write set once before writing local
      JSON records
    - unit coverage proves the Rust write-set request includes every record path
      written by `writeRunRecord`
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_plans_runtime_state_storage_writes_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves Rust plans all storage
      records before the first JSON write and returns hash-bound admissions for
      each record
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still assembles run-state record payloads and performs local JSON file
        writes after Rust transition and write-set planning; the long-term shape
        is for the extracted Rust daemon core to own record materialization and
        persistence in-process
      - runtime Agentgres admission remains command-bridge based until the Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 77

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-77
  phase: 10
  objective: expose runtime run-state storage write-set planning through the
    Rust kernel service facade
  owner_boundary:
    route_or_surface: Rust `RuntimeKernelService` API
    authority_gate: unchanged
    execution_backend: Rust Agentgres admission core
    truth_path: unchanged from Slice 76
    projection_path: unchanged from Slice 76
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/services/src/agentic/runtime/kernel/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `RuntimeKernelService` imports `RuntimeStateStorageWriteSetRequest`
    - `RuntimeKernelService` imports `RuntimeStateStorageWriteSetRecord`
    - `RuntimeKernelService` exposes `plan_runtime_state_storage_writes`
  verification:
    commands:
      - cargo test -p ioi-services agentgres_admission
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: not_applicable
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - runtime Agentgres admission remains command-bridge based until the Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 78

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-78
  phase: 10
  objective: move runtime run-state record materialization into Rust
  owner_boundary:
    route_or_surface: runtime run-state record materialization
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: Rust Agentgres admission command bridge
    truth_path: Rust materializes the ordered run-state record list and payload
      shapes after Rust transition planning and before Rust storage write-set
      planning; JS normalizes the returned records and performs the local JSON
      writes only after Rust returns storage admissions
    projection_path: canonical projection payload is passed into Rust
      materialization and returned with the Agentgres transition bound into the
      projection record
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust Agentgres admission core exposes
      `RuntimeStateRecordMaterializationRequest`
    - `RuntimeKernelService` exposes `materialize_runtime_state_records`
    - command bridge exposes `materialize_runtime_state_records`
    - daemon runtime Agentgres runner exposes `materializeRuntimeStateRecords`
    - `writeRunRecord` obtains Rust-materialized records before requesting the
      Rust storage write set
    - unit coverage proves the materialization request carries run, task, job,
      checklist, canonical projection, and Agentgres transition inputs
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_materializes_runtime_state_records_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves materialization occurs
      before storage admission and every materialized record path is the input
      to Rust storage write-set planning
  cleanup:
    legacy_paths_removed: false
    compatibility_shims_remaining:
      - JS still derives runtime task/job/checklist helper payloads and performs
        local JSON file writes after Rust materialization and storage planning;
        the next cleanup target is for the extracted Rust daemon core to own
        those helper projections and persistence in-process
      - runtime Agentgres admission remains command-bridge based until the Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 79

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-79
  phase: 10
  objective: derive runtime run-state transition hashes and helper records in
    Rust from the run payload
  owner_boundary:
    route_or_surface: runtime run-state transition planning and record
      materialization
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: Rust Agentgres admission command bridge
    truth_path: JS sends the run payload, expected heads, prior state root,
      projection refs, receipt refs, artifact refs, and payload refs; Rust now
      derives the run-state hash, task-state hash, runtime task record, runtime
      job record, runtime checklist record, state_root_after, resulting head,
      transition hash, materialized records, storage write set, and storage
      admissions before any local JSON write
    projection_path: unchanged from Slice 78
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `RuntimeStateTransitionRequest` carries `run` instead of JS-supplied
      `run_state_hash` and `task_state_hash`
    - Rust Agentgres admission core derives `runtime_run_state_hash` and
      `runtime_task_state_hash`
    - Rust Agentgres admission core derives runtime task, job, and checklist
      records for materialization
    - `writeRunRecord` no longer calls JS runtime task/job/checklist projection
      helpers
    - unit coverage proves JS transition and materialization requests do not
      include legacy hash/helper fields
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_plans_runtime_run_state_transition_through_rust_core
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_materializes_runtime_state_records_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves the JS write path sends
      one run payload to Rust and receives Rust-derived transition hashes plus
      Rust-derived runtime task/job/checklist records before storage admission
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS still performs local JSON file writes after Rust transition,
        materialization, and storage planning; the next cleanup target is for
        the extracted Rust daemon core to own persistence in-process
      - runtime Agentgres admission remains command-bridge based until the Rust
        daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 80

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-80
  phase: 10
  objective: route runtime run-state JSON persistence through the Rust
    Agentgres command path
  owner_boundary:
    route_or_surface: runtime run-state persistence after transition planning
    authority_gate: unchanged; caller-owned run lifecycle and cancellation gates
      still run before persistence
    execution_backend: Rust Agentgres persistence command bridge
    truth_path: JS sends the run payload, canonical projection, Rust-planned
      transition, storage backend ref, and receipt refs; Rust composes the
      materialization and storage write-set plan, computes the persistence hash,
      admits every storage write with PayloadRefs/receipt refs, and writes the
      local JSON records under the runtime state directory
    projection_path: unchanged from Slice 79
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust Agentgres admission core exposes `RuntimeStatePersistenceRequest`
      and `RuntimeStatePersistenceRecord`
    - `RuntimeKernelService` exposes `plan_runtime_state_persistence`
    - the Rust bridge command `persist_runtime_state_records` writes admitted
      runtime state records under the provided state directory
    - `writeRunRecord` calls `persistRunStateRecords` and no longer calls JS
      materialization, storage-write-set planning, or local `writeJson`
    - unit coverage proves JS persistence requests carry no legacy helper
      fields and that lower-level JS materialization/storage paths are unused
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_persists_runtime_state_records_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves the JS write path sends
      one persistence request to Rust and receives Rust-written record evidence
      without calling JS local JSON writes
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - runtime Agentgres persistence still crosses the command bridge until
        the extracted Rust daemon core owns the hot path in-process
      - lower-level materialization and storage write-set commands remain as
        Rust conformance/debug surfaces, but `writeRunRecord` no longer uses
        them as its execution path
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 81

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-81
  phase: 11
  objective: retire lower-level JS runtime Agentgres materialization and
    storage-write-set facade methods after Rust persistence became canonical
  owner_boundary:
    route_or_surface: runtime-daemon Agentgres admission runner facade and
      runtime state store facade
    authority_gate: unchanged; run lifecycle gates still precede persistence
    execution_backend: Rust Agentgres persistence command bridge
    truth_path: JS can plan a run-state transition and then request
      `persist_runtime_state_records`; JS no longer exposes
      `materializeRuntimeStateRecords` or `planRuntimeStateStorageWrites` as
      runtime-daemon methods
    projection_path: unchanged from Slice 80
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/index.mjs
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - runtime daemon Agentgres runner exposes `persistRuntimeStateRecords`
    - runtime daemon Agentgres runner no longer exposes
      `materializeRuntimeStateRecords`, `planRuntimeStateStorageWrites`, or
      their normalization wrappers
    - runtime state store no longer exposes materialization/storage-write-set
      forwarding methods
    - runner unit coverage no longer proves retired JS facade operations
    - Rust core and bridge lower-level materialization/storage commands remain
      only as Rust conformance/debug surfaces
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit and conformance coverage prove JS can no
      longer call the old lower-level runtime-state materialization/storage
      bridge operations through the runtime-daemon facade
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - runtime Agentgres persistence still crosses the command bridge until
        the extracted Rust daemon core owns the hot path in-process
      - Rust lower-level materialization and storage write-set commands remain
        available inside the Rust command bridge for conformance/debug, not as
        JS runtime execution facades
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 82

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-82
  phase: 11
  objective: collapse runtime run-state transition planning and persistence into
    one Rust-owned commit command
  owner_boundary:
    route_or_surface: runtime run-state commit path
    authority_gate: unchanged; run lifecycle gates still precede persistence
    execution_backend: Rust Agentgres run-state commit command bridge
    truth_path: JS sends only the run payload, operation kind, storage backend,
      and canonical projection to `commit_runtime_run_state`; Rust derives prior
      head/state-root, projection watermark, receipt refs, artifact refs,
      PayloadRefs, transition record, materialized state records, storage
      admissions, write-set hash, persistence hash, commit hash, and durable
      runtime-state writes
    projection_path: unchanged reader surfaces; persisted projection watermark
      is now discovered by the Rust bridge during commit
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs
      - packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs
      - packages/runtime-daemon/src/index.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.mjs
      - packages/runtime-daemon/src/threads/thread-persistence.test.mjs
    rust_core:
      - crates/services/src/agentic/runtime/kernel/agentgres_admission.rs
      - crates/services/src/agentic/runtime/kernel/mod.rs
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust Agentgres admission exposes `RuntimeRunStateCommitRequest` and
      `commit_runtime_run_state`
    - Rust bridge exposes `commit_runtime_run_state` and writes the resulting
      records after storage admission
    - runtime daemon Agentgres runner exposes `commitRuntimeRunState`
    - runtime daemon Agentgres runner no longer exposes JS transition planning
      or persistence facade methods
    - `writeRunRecord` calls one Rust commit path and sends no expected heads,
      state roots, projection watermark, receipt refs, artifact refs, or
      PayloadRefs from JS
  verification:
    commands:
      - cargo fmt
      - node --check packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs
      - cargo test -p ioi-services agentgres_admission
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_commits_runtime_run_state_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit and conformance coverage prove JS no
      longer orchestrates the transition/persistence split and that Rust derives
      prior-state binding and storage admission before writing runtime records
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - runtime Agentgres commit still crosses the command bridge until the
        extracted Rust daemon core owns the hot path in-process
      - Rust lower-level transition/materialization/storage/persistence
        commands remain available inside the Rust command bridge for
        conformance/debug, not as JS runtime execution facades
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 83

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-83
  phase: 11
  objective: retire external lower-level runtime-state bridge commands after
    the Rust run-state commit path became canonical
  owner_boundary:
    route_or_surface: runtime Agentgres command bridge surface
    authority_gate: unchanged; this removes compatibility entry points rather
      than changing run lifecycle gates
    execution_backend: Rust Agentgres run-state commit command bridge
    truth_path: external callers can request `commit_runtime_run_state` or
      storage-write admission; transition planning, materialization,
      storage-write-set planning, and persistence remain Rust core internals
      used by commit, not separate bridge operations
    projection_path: unchanged
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon: []
    rust_core:
      - crates/node/src/bin/ioi_step_module_bridge/mod.rs
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - Rust bridge exposes `commit_runtime_run_state`
    - Rust bridge still exposes `admit_storage_backend_write`
    - Rust bridge no longer exposes `plan_runtime_run_state_transition`
    - Rust bridge no longer exposes `materialize_runtime_state_records`
    - Rust bridge no longer exposes `plan_runtime_state_storage_writes`
    - Rust bridge no longer exposes `persist_runtime_state_records`
  verification:
    commands:
      - cargo fmt
      - node --check scripts/conformance/hypervisor-conformance.mjs
      - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_commits_runtime_run_state_through_rust_core
      - npm run hypervisor-conformance:receipts
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: conformance proves the retired bridge command
      names are absent while the canonical commit bridge test still passes
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - runtime Agentgres commit still crosses the command bridge until the
        extracted Rust daemon core owns the hot path in-process
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 84

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-84
  phase: 11
  objective: make Rust workload live the default coding-tool StepModule runner
    and fail closed on explicit daemon_js backend selection
  owner_boundary:
    route_or_surface: coding-tool StepModule runner selection
    authority_gate: existing coding-tool budget/approval gates still precede
      StepModule execution
    execution_backend: Rust workload live by default; shadow/gated modes remain
      explicit migration/test choices
    truth_path: no new Agentgres transition; this removes the silent daemon_js
      default for migrated coding-tool execution
    projection_path: unchanged StepModule result projection
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/step-module-runner.mjs
      - packages/runtime-daemon/src/step-module-runner.test.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - `createStepModuleRunnerFromEnv` defaults to `rust_workload_live`
    - empty backend normalization resolves to `rust_workload_live`
    - `daemon_js` is not a selectable StepModule runner backend
    - runner unit coverage proves explicit daemon_js selection fails closed
  verification:
    commands:
      - node --check packages/runtime-daemon/src/step-module-runner.mjs packages/runtime-daemon/src/step-module-runner.test.mjs packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/step-module-runner.test.mjs packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves tests that still exercise
      JS tool bodies do so through explicit shadow test runners, not through the
      production default
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS coding-tool bodies still exist for explicit shadow/test paths and
        non-authoritative client compatibility until full facade retirement
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 85

```yaml
implementation_slice:
  id: hypervisor-kernel-substrate-slice-85
  phase: 11
  objective: retire direct JS coding-tool execution from the daemon invocation
    surface now that every current coding-tool ID has a Rust live backend
  owner_boundary:
    route_or_surface: runtime coding-tool invocation surface
    authority_gate: existing coding-tool budget/approval gates still precede
      StepModule execution
    execution_backend: Rust workload live only for coding-tool execution
    truth_path: no new Agentgres transition; this removes the daemon JS tool
      body as an execution fallback for migrated coding tools
    projection_path: StepModule result projection still comes from the Rust live
      bridge result
  touched_files:
    docs:
      - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
    daemon:
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
      - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    rust_core: []
    ide: []
    tests:
      - scripts/conformance/hypervisor-conformance.mjs
  conformance_checks:
    - runtime coding-tool invocation surface no longer imports or calls
      `executeCodingTool`
    - non-live coding-tool runner attempts fail closed with
      `coding_tool_rust_workload_live_required`
    - Rust live tests still cover the migrated coding-tool IDs
  verification:
    commands:
      - node --check packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
      - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
      - npm run hypervisor-conformance:bridge
      - npm run hypervisor-conformance
      - git diff --check
    replay_or_shadow_comparison: unit coverage proves a shadow/non-live runner
      is rejected before materialization, command-stream emission, or workspace
      snapshot preparation can occur
  cleanup:
    legacy_paths_removed: true
    compatibility_shims_remaining:
      - JS coding-tool implementation helpers still exist in `coding-tools.mjs`
        until their non-authoritative catalog/schema helpers are separated from
        retired JS execution bodies
  closeout:
    git_diff_check: required
    commit: required
    push: required after verification
```

## Implementation Slice 86

```yaml
slice: 86
phase: 11-authoritative-js-facade-retirement
objective: retire the public JS coding-tool dispatcher export and daemon
  constructor injection after the invocation surface moved to Rust workload live
  only
owner_boundary:
  route_or_surface: runtime coding-tool catalog and daemon construction
  authority_gate: unchanged; coding-tool budget/approval gates still precede
    StepModule execution
  execution_backend: Rust workload live only for coding-tool execution
  truth_path: no new Agentgres transition; this removes a stale daemon JS
    execution hook from the public module surface
  projection_path: unchanged; Rust live StepModule result projection remains the
    accepted coding-tool path
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/coding-tools.mjs
    - packages/runtime-daemon/src/index.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - `coding-tools.mjs` no longer exports `executeCodingTool`
  - runtime daemon construction no longer imports or injects
    `executeCodingTool`
  - bridge conformance fails if the retired dispatcher hook reappears in the
    catalog module, daemon index, or invocation surface
verification:
  commands:
    - node --check packages/runtime-daemon/src/coding-tools.mjs packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs packages/runtime-daemon/src/step-module-runner.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: bridge conformance and focused runtime tests
    prove coding-tool execution still routes through Rust workload live and the
    retired JS dispatcher cannot be imported through daemon construction
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - now-unexported JS coding-tool implementation helpers still exist in
      `coding-tools.mjs`; they are dead legacy code after Slice 86 and should be
      removed once the catalog/schema helpers are separated from implementation
      bodies
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 87

```yaml
slice: 87
phase: 11-authoritative-js-facade-retirement
objective: remove the now-dead private JS coding-tool implementation bodies
  and process/filesystem imports after the public dispatcher hook was retired
owner_boundary:
  route_or_surface: runtime coding-tool catalog module
  authority_gate: unchanged; coding-tool budget/approval gates still precede
    StepModule execution
  execution_backend: Rust workload live only for coding-tool execution
  truth_path: no new Agentgres transition; this deletes stale JS implementation
    bodies that no longer have a daemon execution entry point
  projection_path: unchanged; catalog, summary, artifact range, and ABI
    projection helpers remain non-authoritative support code
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/coding-tools.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails if private JS implementation body names return to
    `coding-tools.mjs`
  - bridge conformance fails if retired coding-tool process/filesystem imports
    return to `coding-tools.mjs`
  - catalog/schema/projection/range/summary helpers continue to exist without a
    JS execution backend
verification:
  commands:
    - node --check packages/runtime-daemon/src/coding-tools.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs packages/runtime-daemon/src/step-module-runner.test.mjs packages/runtime-daemon/src/step-module-abi.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: Rust live coding-tool tests still cover the
    migrated tool IDs while conformance proves no private JS implementation body
    remains available in the catalog module
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - coding-tool catalog/schema/result/range helpers remain in JS as
      non-authoritative protocol support; no JS coding-tool implementation body
      remains in `coding-tools.mjs`
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 88

```yaml
slice: 88
phase: 11-authoritative-js-facade-retirement
objective: retire the stale coding-tool Step/Module ABI default that still
  projected `daemon_native_tool` / `daemon_js`
owner_boundary:
  route_or_surface: Step/Module ABI projection helper for coding tools
  authority_gate: unchanged; ABI projection carries the existing authority and
    approval fields
  execution_backend: default coding-tool projection is `workload_job` /
    `workload_grpc`
  truth_path: no new Agentgres transition; this removes a stale projection
    default that implied daemon JS ownership
  projection_path: coding-tool StepModule projections now default to the Rust
    workload backend; explicit daemon_js remains only as a shadow/negative
    validation fixture
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/step-module-abi.mjs
    - packages/runtime-daemon/src/step-module-abi.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - ABI conformance requires the coding-tool Step/Module default to use
    `workload_job` and `workload_grpc`
  - ABI conformance fails if `executionBackend = "daemon_js"` returns as the
    coding-tool projection default
  - explicit daemon_js validation remains available only for existing
    projection/negative fixtures
verification:
  commands:
    - node --check packages/runtime-daemon/src/step-module-abi.mjs packages/runtime-daemon/src/step-module-abi.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/step-module-abi.test.mjs packages/runtime-daemon/src/step-module-runner.test.mjs packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    - npm run hypervisor-conformance:abi
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: ABI tests prove every coding-tool contract now
    projects to workload-backed Step/Module envelopes by default; runtime tests
    continue proving live execution uses the Rust workload path
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - explicit daemon_js validation remains only so negative/shadow fixtures can
      prove direct JS authoritative mutation fails closed
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 89

```yaml
slice: 89
phase: 5-receipt-and-state-root-unification
objective: remove stale model-mounting local operation-log compatibility
  terminology after receipt/state-root admission moved to Rust Agentgres paths
owner_boundary:
  route_or_surface: model-mounting local store adapter status and lifecycle
    receipt helper
  authority_gate: unchanged; receipt writes still require Rust receipt binding
    and Agentgres admission guards
  execution_backend: unchanged
  truth_path: Agentgres admitted receipts and projections, not a local
    operation-log facade
  projection_path: local receipt/projection store exposes typed projections over
    admitted receipt state
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/io.mjs
    - packages/runtime-daemon/src/model-mounting/store.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-operations.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - receipts conformance fails if model-mounting reintroduces the unused
    `operationCount` / `operation-log.jsonl` reader
  - receipts conformance fails if model-mounting store status or lifecycle
    receipts use `local_operation_log` or `agentgres_canonical_operation_log`
    as live terminology
  - model-mounting receipt evidence uses
    `agentgres_receipt_projection_boundary`
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/io.mjs packages/runtime-daemon/src/model-mounting/store.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/store.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: receipt tests still prove direct writes fail
    closed without Rust binding/admission while conformance proves the live local
    adapter no longer presents itself as an operation-log authority
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - operation-like refs remain only as admitted Agentgres operation refs inside
      receipt details where Rust admission produced them
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 90

```yaml
slice: 90
phase: 7-ctee-private-workspace-module-path
objective: promote cTEE private workspace from validation-only Rust guard to an
  executable Rust kernel bundle with receipt binding, Agentgres admission, and
  projection
owner_boundary:
  route_or_surface: cTEE private workspace StepModule action
  authority_gate: daemon-owned Rust kernel validates custody, leakage, and
    declassification refs before execution admission
  execution_backend: ctee_operator
  truth_path: Agentgres operation admitted through Rust receipt binding with
    expected heads and state-root transition
  projection_path: Rust projection record over the admitted cTEE result
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core:
    - crates/services/src/agentic/runtime/kernel/ctee.rs
    - crates/services/src/agentic/runtime/kernel/mod.rs
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - cTEE conformance fails unless the Rust module exposes an executable
    `CteePrivateWorkspaceExecutionRecord`
  - cTEE conformance fails unless execution binds receipts, admits Agentgres
    truth, and emits Rust projection records
  - Rust unit tests prove accepted cTEE execution carries receipt binding,
    Agentgres admission, projection, and expected-head failure behavior
verification:
  commands:
    - cargo test -p ioi-services ctee_private_workspace
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: cTEE result projection now uses the same
    StepModule result, receipt_binder, Agentgres admission, and projection
    primitives as migrated daemon work
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon/IDE invocation surfaces still need to call the Rust cTEE
      execution bundle for real private workspace runs
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 91

```yaml
slice: 91
phase: 7-ctee-private-workspace-module-path
objective: expose the Rust cTEE private workspace execution bundle through the
  daemon StepModule command bridge
owner_boundary:
  route_or_surface: cTEE private workspace bridge command
  authority_gate: bridge accepts only private_workspace_ctee_action /
    ctee_operator StepModule invocations and leaves custody/declassification
    checks to the Rust cTEE module
  execution_backend: ctee_operator via Rust command bridge
  truth_path: bridge returns Rust receipt binding, accepted receipt append,
    Agentgres admission, and projection artifacts from the cTEE execution record
  projection_path: Rust projection record returned to daemon/IDE callers
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core:
    - crates/node/src/bin/ioi_step_module_bridge/mod.rs
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - cTEE conformance fails unless the command bridge exposes
    `execute_private_workspace_ctee_action`
  - cTEE conformance fails unless the bridge command returns receipt/admission/
    projection artifacts and an accepted receipt append from Rust core
  - Rust bridge unit coverage executes a private workspace cTEE action through
    the command bridge
verification:
  commands:
    - cargo test -p ioi-node bridge_executes_private_workspace_ctee_action_through_rust_core
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: bridge output exposes the same Rust cTEE
    execution record, receipt binding, Agentgres admission, and projection that
    the core module creates
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon/IDE private workspace invocation surfaces still need to call
      the bridge command for live runs
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 92

```yaml
slice: 92
phase: 8-service-package-and-worker-package-invocation-path
objective: add the first Rust worker/service package invocation admission
  primitive over the shared Step/Module contract
owner_boundary:
  route_or_surface: WorkerPackage and ServicePackage invocation admission
  authority_gate: package manifests do not grant authority; invocation admission
    requires daemon/wallet authority grant refs on the StepModule invocation
  execution_backend: workload_grpc, rust_wasm, aiip, and ctee_operator where
    allowed by package kind and StepModule kind/backend validation
  truth_path: optional Agentgres operation admitted through Rust receipt binding
    with expected heads and state-root transition
  projection_path: Rust projection record over the package StepModule result
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core:
    - crates/services/src/agentic/runtime/kernel/marketplace.rs
    - crates/services/src/agentic/runtime/kernel/mod.rs
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - receipts conformance fails unless worker/service package invocation has a
    Rust admission record and kernel facade
  - receipts conformance fails unless package invocation uses StepModuleRouter,
    receipt_binder, Agentgres admission, and Rust projection
  - Rust unit tests prove a WorkerPackage workload invocation is admitted and
    Agentgres package transitions require expected heads
verification:
  commands:
    - cargo test -p ioi-services worker_package
    - cargo test -p ioi-services package_invocation_agentgres_transition_requires_expected_heads
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: package invocation admission now composes the
    same StepModule router, receipt, Agentgres, and projection primitives as
    migrated daemon work
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - package command bridge, daemon product routes, IDE/SDK callers, and AIIP
      delivery surfaces still need to invoke this Rust admission primitive
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Route-Family Owner Map

| Route family | Current live anchor | Current owner | Final owner | Truth path target | Conformance tier | Current status | Deletion or demotion condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `coding-tools` | `packages/runtime-daemon/src/coding-tools.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `packages/runtime-daemon/src/step-module-runner.mjs`, `packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs`, `crates/node/src/bin/ioi-step-module-bridge.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | Rust workload live execution for every current coding tool: workspace.status, git.diff, file.inspect, file.apply_patch, test.run, lsp.diagnostics, artifact.read, tool.retrieve_result, and computer_use.request_lease; JS retains only tool catalog/schema/result/range/summary helper code as non-authoritative protocol support | Rust core `step_router` plus workload/WASM backend | Agentgres admitted operation with receipt, refs, heads, and state roots | `abi`, `bridge`, `receipts`, `negative` | every current coding-tool ID returns a Rust live payload; coding-tool Step/Module projections default to `workload_job` / `workload_grpc`; `createStepModuleRunnerFromEnv` defaults to `rust_workload_live`; explicit `daemon_js` runner selection fails closed; non-live coding-tool runner attempts fail before materialization, command-stream emission, workspace snapshot preparation, or JS tool-body execution; `executeCodingTool` is no longer exported, imported, injected, or accepted by bridge conformance; private JS implementation bodies and their process/filesystem imports are removed from the catalog module | Rust path passes shadow, gated, and live parity for each migrated tool; JS can no longer append authoritative effects. |
| `approvals-gates` | `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `crates/services/src/agentic/runtime/kernel/authority.rs` | JS daemon routes plus Rust external-exit authority guard | Rust core `authority` with wallet.network handoff | authority grant and approval receipt before effect boundary | `bridge`, `negative` | Rust wallet.network guard implemented for external exits; live JS approval surface remains | JS can only request/render approvals; grants and gate decisions are issued by Rust authority core and wallet.network. |
| `runtime-events-replay-trace` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` | JS daemon envelope/projection code | Rust core `projection` plus Agentgres projection watermarks | replayable projection over admitted operations and receipts | `receipts`, `compositor` | JS projection source | Rust emits canonical projection records consumed by IDE/CLI/SDK. |
| `model-mounting` | `packages/runtime-daemon/src/model-mounting/*`, `packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/model_mount.rs` | JS daemon model-mounting store/provider control surfaces plus extracted JS receipt-write guard policy, Rust route-decision, provider-execution, fixture and native-local non-stream provider-invocation execution, native-local stream invocation planning/chunks, local-provider health/load/unload lifecycle result-envelope planning with provider-health receipt guards and fail-closed local provider start/stop control, local-provider model/list-loaded inventory result-envelope planning with provider-inventory lifecycle-receipt guards, migrated local-provider model-instance lifecycle transition planning for load/unload/evict/supersede with direct-write and provider-kind-bound lifecycle-receipt guards, provider-result admission for non-migrated driver and stream-start observations, invocation-receipt admission, receipt_binder binding, Agentgres admission for invocation and stream-completion receipts, retired provider-open retry, wallet authority audit, vault audit, receipt-store, OpenAI provider stream-shape operation-like appends, and stale daemon append callback injection, and guards against unbound direct invocation and model lifecycle receipt appends | Rust core `model_mount` | model invocation receipts, provider-execution/invocation/result receipts, route/custody refs, Agentgres operation | `abi`, `bridge`, `receipts`, `ctee` | live route-selection, provider-execution admission, fixture and native-local non-stream provider invocation execution, native-local stream frame planning/chunks, fixture and native-local health/load/unload lifecycle result envelope planning, fixture and native-local model/list-loaded inventory result envelope planning, migrated local-provider model load/unload/evict/supersede instance lifecycle transition planning, non-migrated provider-result admission for hosted/non-migrated non-stream and stream-start observations, and model-invocation receipts call Rust model_mount; direct JS local provider non-stream `invoke()` and native-local stream production shims now fail closed, dead native-local JS stream helper exports are removed, the obsolete JS native-local output wrapper is deleted, and retired JS native fixture response modules are gone; the provider-invocation bridge now uses the shared `execute_model_mount_provider_invocation` operation instead of a fixture-only command; native-local stream invocations use `execute_model_mount_provider_stream_invocation` and JS only adapts returned Rust chunks into the protocol stream facade; fixture and native-local health/load/unload calls use `plan_model_mount_provider_lifecycle` while JS still supervises process state and persists provider/model-instance lifecycle receipts; direct migrated local-provider `provider_health` receipt writes now fail closed without provider kind and Rust lifecycle action/status/hash/evidence through the extracted receipt-write guard module; migrated local-provider `provider_start`/`provider_stop` now fail closed without Rust lifecycle binding, and direct store writes for those receipts require the same Rust binding; fixture and native-local listModels/listLoaded calls use `plan_model_mount_provider_inventory` while JS still reads state records; migrated local provider `loadModel`/`unloadModel` calls and idle-evict/supersede transitions use `plan_model_mount_instance_lifecycle` before JS writes model-instance state; direct migrated local-provider `model-instances` map writes now fail closed without Rust instance lifecycle action/status hashes and evidence; direct migrated local-provider model lifecycle receipt helper and store writes now fail closed without provider kind and the same Rust binding; direct migrated local-provider provider-inventory receipt writes now fail closed without provider kind and Rust inventory action/status/hash/evidence through the extracted receipt-write guard module; stream request-shape evidence no longer appends a duplicate JS operation-like record, provider-open retry handling no longer appends a duplicate operation-like retry record, wallet/vault audit mirroring no longer appends local `wallet.*` or `vault.*` operation-like records, receipt persistence no longer appends duplicate daemon operation-log records or exposes the old `operationCount`/`operation-log.jsonl` reader, OpenAI provider stream-shape evidence is bound into stream-completion receipts instead of appended as duplicate operation-like truth, and the runtime store no longer injects daemon-local `appendOperation` into `ModelMountingState` after Rust binding/admission; model-mounting local heads and projection watermarks now derive from persisted receipt count, and the local adapter identifies as a receipt/projection store rather than a local operation-log authority; native stream requests now fail closed before or after stream-start admission instead of downgrading into non-stream invocation; OpenAI-compatible `responses` calls now fail closed instead of translating to chat-completions provider results; provider compatibility-translation markers now fail closed before provider-result admission and no longer enter accepted receipts or native responses; protocol response helpers are no longer re-exported through the broad model-mounting compatibility facade; invocation and stream-completion receipts are represented as `model_mount` StepModule results and bound by Rust receipt_binder plus Rust Agentgres admission before JS store persistence; direct JS store append of unbound invocation receipts now fails closed through the extracted guard module; hosted/non-migrated request/response/load/unload and stream transports, local provider state-record reads, native-local process supervision/logging, non-migrated lifecycle receipt persistence, and broader JS store demotion still remain | Rust records route decisions, provider execution admission, migrated provider invocation execution, native-local stream invocation chunks, local-provider lifecycle and inventory result envelopes, migrated local-provider model-instance lifecycle transitions, admitted non-migrated provider observations, stream-start observations, and receipts; JS provider/store surfaces are demoted as each remaining provider backend moves behind Rust workload/model_mount execution ownership. |
| `agentgres-admission` | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs`, `.ioi/agentgres` local state, `crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`, `docs/architecture/components/agentgres/*` | daemon-local operation-like records plus Rust admission/storage guards; memory record/policy, runtime-bridge turn budget/error, agent delete, agent/subagent persistence, and run persistence operation mirroring retired; run-state persistence now sends only the run payload, operation kind, storage backend, and canonical projection through the Rust Agentgres commit command, where Rust derives prior heads/state roots, projection watermark, refs, runtime run/task hashes, runtime task/job/checklist materializations, storage admissions, and durable writes; model invocation and stream-completion receipt operations now enter Rust Agentgres admission and unbound direct store appends are rejected | Rust core `agentgres_admission` | expected heads, state-root validation, accepted operation admission | `receipts`, `negative` | Rust operation admission and storage-write guards implemented; Rust runtime-state commit now derives expected heads, state_root_before, run_state_hash, task_state_hash, state_root_after, resulting_head, projection watermark, transition hash, materialized run/task/job/checklist/sidecar/projection records, content hashes, object refs, PayloadRefs, storage admissions, write-set hash, persistence hash, commit hash, and Rust-written local JSON records from one JS commit request; the runtime-daemon JS facade and Rust command bridge no longer expose lower-level transition planning, materialization, storage-write-set, or persistence methods as execution entry points; runtime Agentgres admission requires `IOI_RUNTIME_AGENTGRES_COMMAND` and no longer reuses the model-mount command env as a fallback; model invocation and stream-completion receipt operations carry expected-head/state-root admission; direct unbound invocation receipt store writes fail closed; memory record/policy updates no longer mirror `memory.*` operation-log records; runtime bridge turn submits no longer mirror budget/error operation records; guarded agent deletion no longer mirrors `agent.delete`; agent/subagent record writes no longer append operation-log mirrors; run persistence no longer appends operation-log records and now leaves prior transition lookup to Rust commit; runtime read, doctor, tool, and turn projection surfaces no longer expose the daemon-local operation log | no JS path can append accepted operations directly or mutate durable truth without expected heads/state-root binding and storage ArtifactRef/PayloadRef admission. |
| `receipt-binding` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/ipc/proto/public/v1/public.proto`, `crates/services/src/agentic/runtime/kernel/receipt_binder.rs` | JS receipts plus Rust receipt binder and append guard | Rust core `receipt_binder` | one binder for invocation, result, artifact refs, payload refs, and state roots | `receipts`, `negative` | binder primitive and direct-append guard implemented; JS receipts still live | every meaningful route family emits receipts through one Rust binder. |
| `ctee-private-workspace` | `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`, `crates/services/src/agentic/runtime/kernel/ctee.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs` | canon plus Rust StepModule validation, execution, receipt-binding, Agentgres admission, projection bundle, and daemon command bridge exposure | Rust core `ctee` | custody proof, leakage profile, declassification receipt, plaintext-free mount failure | `ctee`, `negative` | Rust validation and execution/admission/projection bundle implemented and exposed through `execute_private_workspace_ctee_action`; product daemon/IDE private workspace callers still pending | untrusted node plaintext mount fails closed; declassification and private operator paths are receipt-bound. |
| `workload-client-wasm` | `crates/client/src/workload_client/mod.rs`, `crates/vm/wasm/src/lib.rs`, `crates/validator/src/standard/workload/*` | Rust workload/kernel substrate exists below daemon | Rust core `workload_client` plus WASM/service backend | StepModuleResult with workload receipt and state-root binding | `bridge`, `receipts` | substrate exists, not default daemon backend | daemon routes admitted work through StepModuleRunner into Rust/WASM or workload backend. |
| `workflow-compositor` | `packages/agent-ide/src/runtime/*`, `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/services/src/agentic/runtime/kernel/projection.rs` | IDE/daemon projection shaping plus Rust projection record primitive | Rust core `projection` consumed by IDE/CLI/SDK | projection checkpoints rebuilt from Agentgres admitted truth | `compositor`, `negative` | Rust projection record and accepted-truth guard implemented; IDE/SDK consumption still pending | compositor cannot create accepted truth directly and only renders/replays canonical projections. |
| `worker-service-packages` | `docs/architecture/foundations/common-objects-and-envelopes.md`, `docs/architecture/domains/aiagent/worker-endpoints.md`, `docs/architecture/domains/sas/service-endpoints.md`, `crates/services/src/agentic/runtime/kernel/marketplace.rs` | target canon plus Rust worker/service package invocation admission primitive over StepModuleRouter, receipt_binder, Agentgres admission, and projection | Rust core `step_router` plus workload/WASM/AIIP backends | package invocation receipt, authority grant, artifacts, projection | `bridge`, `receipts`, `compositor` | Rust package invocation admission primitive implemented; bridge/product/IDE callers still pending | service and worker package invocation uses the shared Step/Module ABI. |
| `l1-settlement` | `docs/architecture/foundations/ioi-l1-mainnet.md`, `crates/services/src/agentic/runtime/kernel/settlement.rs` | canon plus Rust trigger guard | Rust settlement/admission core under daemon-owned execution | sparse public/economic/cross-domain commitment by trigger only | `negative` | Rust trigger guard implemented; product settlement surfaces still pending | L1 settlement attempts without marketplace/public/economic/cross-domain/operator trigger fail closed. |
| `meta-improvement` | `crates/services/src/agentic/runtime/kernel/*`, workflow/evaluation docs | partial Rust/IDE signals | Rust core authority plus proposal/eval/approval path | proposal object, eval receipts, approval grant, committed mutation | `receipts`, `negative` | target only | agents cannot self-modify directly; all improvements are proposal-mediated. |
| `rust-daemon-core` | target layout in master guide plus `crates/services/src/agentic/runtime/kernel/*` | partial Rust primitives for authority, step_router, cTEE, receipts, Agentgres admission, runtime-state transition planning, run/task hash derivation, helper record materialization, storage write-set planning, runtime-state persistence planning, runtime run-state commit planning, projection, settlement, Step/Module ABI, model_mount provider-execution admission, fixture/native-local non-stream provider-invocation execution, native-local stream invocation planning/chunks, and provider-result admission for non-migrated driver observations | Rust modules: `authority`, `step_router`, `workload_client`, `model_mount`, `ctee`, `receipt_binder`, `agentgres_admission`, `projection`, `conformance` | one Rust owner for hot-path semantics | all tiers | partial primitives, not extracted as one authoritative core; coding tools now execute through Rust workload live instead of the daemon JS invocation body; model_mount now admits provider-execution envelopes before JS provider driver calls, executes migrated fixture/native-local non-stream provider backends and native-local stream chunk planning, rejects retired direct JS local provider non-stream/stream execution shims, admits non-migrated JS provider results before receipts, and runtime run persistence now sends one commit request through `RuntimeKernelService`, where Rust derives prior transition binding, transition hashes, materialized state records, storage write sets, persistence hashes, commit hashes, and Rust-written local state records; the external bridge exposes the commit operation instead of separate transition/materialization/storage/persistence commands | hot-path execution, authority, receipt/state-root binding, cTEE, replay, and conformance are owned by Rust core. |
| `js-facade-retirement` | `packages/runtime-daemon/src/*`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | JS is current live daemon implementation, with Rust guard forbidding authoritative daemon_js mutation | non-authoritative product/API/client facade only where useful | stable protocol APIs into Rust core | `negative`, terminal `hypervisor-conformance` | direct JS authoritative mutation guard implemented; coding-tool ABI projections no longer default to `daemon_js`; StepModule runner no longer defaults to or accepts `daemon_js`; runtime coding-tool invocation no longer imports or calls the JS `executeCodingTool` body, daemon construction no longer imports or injects that retired dispatcher, and the private JS coding-tool implementation bodies are removed; model-mounting protocol response compatibility re-export retired; broad live facade retirement still pending | every migrated route family removes or demotes old JS authoritative paths and compatibility shims. |

## Cleanup Targets Found In Phase 0

These are not deletions for Slice 0. They are the long-term cleanup targets that
must be retired as the corresponding route family reaches verified parity:

| Cleanup target | Why it must not be permanent | Removal trigger |
| --- | --- | --- |
| Direct JS coding tool dispatch for consequential effects | It is the current split-brain authoritative execution path. | Each tool has ABI coverage, Rust/WASM or workload execution, receipts/state roots, and compositor parity. |
| Daemon-local operation-like truth outside Rust Agentgres admission | It risks duplicate accepted truth. | Agentgres admission enforces expected heads and state-root binding for meaningful transitions. |
| Receipt emission in multiple owners | Duplicate receipt paths make replay and failure analysis ambiguous. | `receipt_binder` owns all accepted receipt/result binding. |
| Model/provider fallback routes outside daemon-owned model mounting | Earlier parity work established daemon-owned mounting/routing as source of truth. | Rust `model_mount` owns route decisions, provider-execution admission, migrated fixture/native-local non-stream provider invocation execution, native-local stream invocation planning/chunks, non-migrated provider-result admission, and receipts. |
| Compatibility adapters that can mutate state or emit accepted receipts | Alpha has no need to preserve old route behavior after migration. | Stable protocol APIs exist and migrated route families pass negative conformance. |
| Workflow compositor accepted-truth shortcuts | The IDE should compose and inspect, not admit truth. | compositor projections rebuild from Agentgres operations and Rust projection watermarks. |
| cTEE language without runtime plaintext-failure tests | cTEE is no-plaintext-custody private workspace execution, not encryption-at-rest. | private workspace module path and leakage/declassification tests pass. |
| Default or silent L1 settlement attempts | IOI L1 is for sparse public/economic/cross-domain commitments, not default runtime settlement. | L1 settlement attempts route through Rust trigger admission and fail without trigger refs. |

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

Current expected behavior after Slice 92:

| Command | Expected status now | Reason |
| --- | --- | --- |
| `hypervisor-conformance:docs` | pass | Phase 0 inventory, source map, matrix, command wiring, and stale-term guard exist. |
| `hypervisor-conformance:abi` | pass | Step/Module schemas and current coding-tool projection wrappers exist, and coding-tool projections default to `workload_job` / `workload_grpc` instead of daemon_js. |
| `hypervisor-conformance:bridge` | pass | daemon StepModuleRunner boundary defaults to Rust workload live, explicit `daemon_js` backend selection fails closed, runtime coding-tool invocation requires Rust workload live, the retired JS `executeCodingTool` dispatcher is no longer present in the invocation surface, catalog module export surface, or daemon constructor injection, private JS coding-tool implementation bodies and their process/filesystem imports are absent from `coding-tools.mjs`, live Rust model_mount provider-execution admission bridge, shared Rust provider invocation bridge for fixture and native-local non-stream execution, Rust native-local stream invocation bridge and returned-chunk adapter, Rust local-provider lifecycle planner bridge for fixture/native-local health/load/unload result envelopes, Rust local-provider inventory planner bridge for fixture/native-local model/list-loaded result envelopes, Rust instance lifecycle planner bridge for migrated local-provider model load/unload/evict/supersede state transitions, retired direct JS local provider non-stream invoke and native-local stream production shims, removed dead JS native-local stream helper exports, obsolete output wrapper, and retired fixture response modules, Rust provider-result admission bridge, stream-start provider-result admission guard, native-stream no-downgrade guards, OpenAI-compatible responses no-fallback guard, provider compatibility-translation fail-closed guard, and protocol response facade re-export retirement guard exist without a duplicate JS request-shape append. |
| `hypervisor-conformance:receipts` | pass | Rust StepModule receipt binder exists, model provider execution is admitted before driver calls, fixture and native-local non-stream provider invocation execute in Rust, native-local stream frame planning/chunks execute in Rust, local-provider health/load/unload lifecycle status/backend/evidence envelopes are planned and hash-bound in Rust, local-provider model/list-loaded inventory status/backend/evidence envelopes are planned and hash-bound in Rust, migrated local-provider model load/unload/evict/supersede instance lifecycle transitions are planned and hash-bound in Rust to provider lifecycle hashes, direct migrated local-provider model-instance map and lifecycle receipt helper/store persistence without provider kind and Rust instance lifecycle action/status hashes now fails closed, direct migrated local-provider provider-health receipt persistence without provider kind and Rust lifecycle action/status/hash/evidence now fails closed, migrated local-provider provider start/stop fails closed without Rust lifecycle binding and direct provider-control receipt persistence requires the same binding, direct migrated local-provider provider-inventory receipt persistence without provider kind and Rust inventory action/status/hash/evidence now fails closed, the direct receipt-write guards now live outside the JS store adapter in `model-mounting/receipt-write-guards.mjs`, non-migrated provider results and native stream-start observations are Rust-admitted observations, runtime run-state persistence sends one commit request to Rust, where Agentgres admission derives prior heads/state roots, projection watermark, receipt/artifact/payload refs, run-state and task-state hashes, runtime task/job/checklist materializations, storage admissions, write-set hash, persistence hash, commit hash, and Rust-written local JSON records; `writeRunRecord` no longer calls JS transition planning, JS persistence, JS materialization, storage write-set planning, or local `writeJson`, and neither the runtime-daemon JS facade nor the Rust command bridge exposes lower-level transition/materialization/storage-write-set/persistence methods as execution entry points, runtime Agentgres admission requires the explicit `IOI_RUNTIME_AGENTGRES_COMMAND` env without model-mount env fallback, stream request-shape evidence, provider-open retry handling, wallet authority audit mirroring, vault audit mirroring, receipt persistence and model-mount local adapter status no longer expose local operation-log terminology or an `operation-log.jsonl` reader, OpenAI provider stream-shape recording, stale model-mounting append callback injection, memory record/policy operation mirroring, runtime bridge turn budget/error mirroring, agent delete operation mirroring, agent/subagent persistence operation mirroring, and run persistence/read-surface operation-log exposure no longer create duplicate JS operation-like records; model-mounting local heads and projection watermarks derive from persisted receipt count; model invocation and stream-completion receipts carry Rust Agentgres admission, direct unbound model invocation store appends fail closed, and worker/service package invocation has a Rust admission primitive over StepModuleRouter, receipt_binder, Agentgres admission, and projection. |
| `hypervisor-conformance:ctee` | pass | Rust cTEE Private Workspace module validation exists, untrusted plaintext custody fails closed, the Rust cTEE action bundle binds receipts, admits Agentgres truth, and emits projection records, and the daemon command bridge exposes that bundle through `execute_private_workspace_ctee_action`. |
| `hypervisor-conformance:compositor` | pass | Rust projection records exist, the shadow bridge emits them, and compositor accepted-truth attempts fail closed. |
| `hypervisor-conformance:negative` | pass | All required forbidden-path negative fixtures are implemented at the Rust guard level. |
| `hypervisor-conformance` | pass at current tier surface | Current wired tiers pass; terminal migration is still not claimed until live route families are routed through Rust core and JS facade retirement is complete. |
