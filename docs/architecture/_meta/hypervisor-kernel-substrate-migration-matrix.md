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

## Route-Family Owner Map

| Route family | Current live anchor | Current owner | Final owner | Truth path target | Conformance tier | Current status | Deletion or demotion condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `coding-tools` | `packages/runtime-daemon/src/coding-tools.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `packages/runtime-daemon/src/step-module-runner.mjs`, `crates/node/src/bin/ioi-step-module-bridge.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | JS daemon tool dispatch with Step/Module projection wrappers plus live Rust paths for workspace.status, git.diff, file.inspect, all test.run command backends, and all lsp.diagnostics command backends | Rust core `step_router` plus workload/WASM backend | Agentgres admitted operation with receipt, refs, heads, and state roots | `abi`, `bridge`, `receipts`, `negative` | `workspace.status`, `git.diff`, `file.inspect`, all `test.run` command backends, and all `lsp.diagnostics` command backends return Rust live payloads without daemon_js; mutating/retrieval coding tools still need routing/demotion | Rust path passes shadow, gated, and live parity for each migrated tool; JS can no longer append authoritative effects. |
| `approvals-gates` | `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `crates/services/src/agentic/runtime/kernel/authority.rs` | JS daemon routes plus Rust external-exit authority guard | Rust core `authority` with wallet.network handoff | authority grant and approval receipt before effect boundary | `bridge`, `negative` | Rust wallet.network guard implemented for external exits; live JS approval surface remains | JS can only request/render approvals; grants and gate decisions are issued by Rust authority core and wallet.network. |
| `runtime-events-replay-trace` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` | JS daemon envelope/projection code | Rust core `projection` plus Agentgres projection watermarks | replayable projection over admitted operations and receipts | `receipts`, `compositor` | JS projection source | Rust emits canonical projection records consumed by IDE/CLI/SDK. |
| `model-mounting` | `packages/runtime-daemon/src/model-mounting/*` | JS daemon model-mounting store and route policy | Rust core `model_mount` | model invocation receipts, route/custody refs, Agentgres operation | `bridge`, `receipts`, `ctee` | live product daemon state | Rust records route decisions and receipts; JS surfaces are non-authoritative clients. |
| `agentgres-admission` | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs`, `.ioi/agentgres` local state, `crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`, `docs/architecture/components/agentgres/*` | daemon-local operation-like records plus Rust admission/storage guards | Rust core `agentgres_admission` | expected heads, state-root validation, accepted operation admission | `receipts`, `negative` | Rust operation admission and storage-write guards implemented; live JS append/write surfaces still need routing/demotion | no JS path can append accepted operations directly or mutate durable truth without expected heads/state-root binding. |
| `receipt-binding` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/ipc/proto/public/v1/public.proto`, `crates/services/src/agentic/runtime/kernel/receipt_binder.rs` | JS receipts plus Rust receipt binder and append guard | Rust core `receipt_binder` | one binder for invocation, result, artifact refs, payload refs, and state roots | `receipts`, `negative` | binder primitive and direct-append guard implemented; JS receipts still live | every meaningful route family emits receipts through one Rust binder. |
| `ctee-private-workspace` | `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`, `crates/services/src/agentic/runtime/kernel/ctee.rs` | canon plus Rust StepModule validation boundary | Rust core `ctee` | custody proof, leakage profile, declassification receipt, plaintext-free mount failure | `ctee`, `negative` | Rust validation path implemented; full execution/admission/projection still pending | untrusted node plaintext mount fails closed; declassification and private operator paths are receipt-bound. |
| `workload-client-wasm` | `crates/client/src/workload_client/mod.rs`, `crates/vm/wasm/src/lib.rs`, `crates/validator/src/standard/workload/*` | Rust workload/kernel substrate exists below daemon | Rust core `workload_client` plus WASM/service backend | StepModuleResult with workload receipt and state-root binding | `bridge`, `receipts` | substrate exists, not default daemon backend | daemon routes admitted work through StepModuleRunner into Rust/WASM or workload backend. |
| `workflow-compositor` | `packages/agent-ide/src/runtime/*`, `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/services/src/agentic/runtime/kernel/projection.rs` | IDE/daemon projection shaping plus Rust projection record primitive | Rust core `projection` consumed by IDE/CLI/SDK | projection checkpoints rebuilt from Agentgres admitted truth | `compositor`, `negative` | Rust projection record and accepted-truth guard implemented; IDE/SDK consumption still pending | compositor cannot create accepted truth directly and only renders/replays canonical projections. |
| `worker-service-packages` | `docs/architecture/foundations/common-objects-and-envelopes.md`, `docs/architecture/domains/aiagent/worker-endpoints.md`, `docs/architecture/domains/sas/service-endpoints.md` | target canon plus service/module concepts | Rust core `step_router` plus workload/WASM/AIIP backends | package invocation receipt, authority grant, artifacts, projection | `bridge`, `receipts`, `compositor` | target only | service and worker package invocation uses the shared Step/Module ABI. |
| `l1-settlement` | `docs/architecture/foundations/ioi-l1-mainnet.md`, `crates/services/src/agentic/runtime/kernel/settlement.rs` | canon plus Rust trigger guard | Rust settlement/admission core under daemon-owned execution | sparse public/economic/cross-domain commitment by trigger only | `negative` | Rust trigger guard implemented; product settlement surfaces still pending | L1 settlement attempts without marketplace/public/economic/cross-domain/operator trigger fail closed. |
| `meta-improvement` | `crates/services/src/agentic/runtime/kernel/*`, workflow/evaluation docs | partial Rust/IDE signals | Rust core authority plus proposal/eval/approval path | proposal object, eval receipts, approval grant, committed mutation | `receipts`, `negative` | target only | agents cannot self-modify directly; all improvements are proposal-mediated. |
| `rust-daemon-core` | target layout in master guide plus `crates/services/src/agentic/runtime/kernel/*` | partial Rust primitives for authority, step_router, cTEE, receipts, Agentgres admission, projection, settlement, and Step/Module ABI | Rust modules: `authority`, `step_router`, `workload_client`, `model_mount`, `ctee`, `receipt_binder`, `agentgres_admission`, `projection`, `conformance` | one Rust owner for hot-path semantics | all tiers | partial primitives, not extracted as one authoritative core | hot-path execution, authority, receipt/state-root binding, cTEE, replay, and conformance are owned by Rust core. |
| `js-facade-retirement` | `packages/runtime-daemon/src/*`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | JS is current live daemon implementation, with Rust guard forbidding authoritative daemon_js mutation | non-authoritative product/API/client facade only where useful | stable protocol APIs into Rust core | `negative`, terminal `hypervisor-conformance` | direct JS authoritative mutation guard implemented; broad live facade retirement still pending | every migrated route family removes or demotes old JS authoritative paths and compatibility shims. |

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

Current expected behavior after Slice 22:

| Command | Expected status now | Reason |
| --- | --- | --- |
| `hypervisor-conformance:docs` | pass | Phase 0 inventory, source map, matrix, command wiring, and stale-term guard exist. |
| `hypervisor-conformance:abi` | pass | Step/Module schemas and current coding-tool projection wrappers exist. |
| `hypervisor-conformance:bridge` | pass | daemon StepModuleRunner boundary and fail-closed Rust workload runner selection exist. |
| `hypervisor-conformance:receipts` | pass | Rust StepModule receipt binder exists and the Rust shadow bridge emits a receipt binding. |
| `hypervisor-conformance:ctee` | pass | Rust cTEE Private Workspace module validation exists and untrusted plaintext custody fails closed. |
| `hypervisor-conformance:compositor` | pass | Rust projection records exist, the shadow bridge emits them, and compositor accepted-truth attempts fail closed. |
| `hypervisor-conformance:negative` | pass | All required forbidden-path negative fixtures are implemented at the Rust guard level. |
| `hypervisor-conformance` | pass at current tier surface | Current wired tiers pass; terminal migration is still not claimed until live route families are routed through Rust core and JS facade retirement is complete. |
