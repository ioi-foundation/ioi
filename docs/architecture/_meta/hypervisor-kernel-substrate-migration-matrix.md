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
    truth_path: route-selection receipts carry the Rust `model_mount_route_decision`
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
    - scripts/lib/workflow-runtime-event-projection-contract.test.mjs
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

## Implementation Slice 93

```yaml
slice: 93
phase: 8-service-package-and-worker-package-invocation-path
objective: expose worker/service package invocation admission through the daemon
  StepModule command bridge
owner_boundary:
  route_or_surface: worker/service package bridge command
  authority_gate: bridge forwards package StepModule requests to Rust admission;
    Rust rejects missing daemon/wallet authority grant refs
  execution_backend: rust_package_invocation bridge over workload_grpc,
    rust_wasm, aiip, or ctee_operator StepModule backends
  truth_path: bridge returns Rust router admission, receipt binding, accepted
    receipt append, optional Agentgres admission, and projection artifacts
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
  - bridge conformance fails unless `admit_worker_service_package_invocation`
    is exposed through the command bridge
  - bridge conformance fails unless the command returns accepted receipt append
    and package admission artifacts from Rust
  - Rust bridge unit coverage admits a worker package invocation through the
    command bridge
verification:
  commands:
    - cargo test -p ioi-node bridge_admits_worker_service_package_invocation_through_rust_core
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: bridge output exposes the same Rust package
    invocation record plus accepted receipt append that daemon callers need
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE/SDK callers, and AIIP delivery surfaces still
      need to invoke the bridge command for live package work
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 94

```yaml
slice: 94
phase: 9-meta-improvement-proposal-path
objective: add a governed runtime-improvement proposal admission primitive with
  eval receipts, approval, rollback, and Agentgres binding
owner_boundary:
  route_or_surface: runtime skill/module/workflow/route/schema/policy
    improvement proposal admission
  authority_gate: improvement proposals require approval refs and cannot become
    live from agent self-mutation alone
  execution_backend: unchanged; proposal admission only
  truth_path: proposal admission requires Agentgres operation ref, expected
    heads, before/after state roots, and resulting head
  projection_path: later IDE/daemon proposal review surface consumes admitted
    proposal records
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core:
    - crates/services/src/agentic/evolution.rs
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - receipts conformance fails unless governed runtime-improvement proposal and
    admission records exist
  - receipts conformance fails unless eval receipts, verifier receipts,
    approval, rollback, Agentgres operation refs, expected heads, and state roots
    are required
  - Rust unit tests prove governed proposal admission and direct self-mutation
    fail-closed behavior
verification:
  commands:
    - cargo test -p ioi-services governed_improvement
    - cargo test -p ioi-services direct_self_mutation_without_governed_proposal_fails_closed
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: meta-improvement candidates can now be represented
    as admitted proposal records before any live mutation path is allowed
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - existing direct `EvolutionService::evolve` manifest mutation path still
      needs routing through or retirement behind the governed proposal admission
    - bridge, daemon product routes, IDE review, and rollback application remain
      pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 95

```yaml
slice: 95
phase: 9-meta-improvement-proposal-path
objective: expose governed runtime-improvement proposal admission through the
  Rust command bridge without applying live mutations
owner_boundary:
  route_or_surface: bridge command for runtime skill/module/workflow/route/schema/policy
    improvement proposal admission
  authority_gate: bridge only admits proposals carrying approval, eval/verifier,
    rollback, Agentgres, expected-head, and state-root bindings
  execution_backend: rust_governed_evolution proposal admission
  truth_path: bridge returns the Rust admission record and Agentgres/state-root
    binding identifiers for daemon/product callers
  projection_path: later IDE/daemon proposal review surface consumes the same
    admitted bridge output
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
  - bridge conformance fails unless `admit_governed_runtime_improvement_proposal`
    is exposed through the command bridge
  - bridge conformance fails unless the command calls `GovernedEvolutionCore`
    and returns the governed meta-improvement source marker
  - Rust bridge unit coverage admits a governed runtime-improvement proposal
    through the command bridge
verification:
  commands:
    - cargo test -p ioi-node bridge_admits_governed_runtime_improvement_proposal_through_rust_core
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: bridge output exposes the same admitted proposal
    record that later daemon/IDE callers can review before any mutation is
    applied
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - existing direct `EvolutionService::evolve` manifest mutation path still
      needs routing through or retirement behind governed proposal admission
    - product daemon routes, IDE review, rollback application, and live mutation
      commit path remain pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 96

```yaml
slice: 96
phase: 9-meta-improvement-proposal-path
objective: retire the legacy direct `EvolutionService::evolve` manifest mutation
  body so runtime improvements must enter through governed proposal admission
owner_boundary:
  route_or_surface: legacy evolution service method
  authority_gate: direct owner-authorized manifest mutation fails closed before
    any state read or write
  execution_backend: none; callers must use governed proposal admission
  truth_path: no direct `evolution::manifest`, `evolution::latest`, or
    `evolution::rationale` state keys are written by the legacy method
  projection_path: unchanged; later proposal review/application surfaces consume
    admitted proposal records
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core:
    - crates/services/src/agentic/evolution.rs
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - receipts conformance fails if the legacy direct manifest keys or
    `AgentManifest` mutation parser return to `evolution.rs`
  - receipts conformance fails unless `EvolutionService::evolve` exposes the
    retired direct mutation marker
  - Rust unit coverage proves direct evolve fails closed without state reads or
    writes
verification:
  commands:
    - cargo test -p ioi-services direct_evolve_manifest_mutation_is_retired_fail_closed
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: legacy direct mutation is no longer a replayable
    truth path; proposal admission is the only implemented meta-improvement
    entry point
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - product daemon routes, IDE review, rollback application, and live mutation
      commit path remain pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 97

```yaml
slice: 97
phase: 9-meta-improvement-proposal-path
objective: add a daemon-side governed-improvement runner that calls the Rust
  proposal admission bridge and fails closed when unconfigured
owner_boundary:
  route_or_surface: non-authoritative daemon facade for governed runtime
    improvement proposal admission
  authority_gate: daemon facade cannot apply proposals; it only forwards proposal
    admission to Rust and surfaces Rust rejection
  execution_backend: rust_governed_evolution through
    `admit_governed_runtime_improvement_proposal`
  truth_path: Rust bridge remains the admission owner; JS normalizes returned
    admission records for later product/API callers
  projection_path: later IDE review surfaces can consume normalized admitted
    proposal records
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-governed-improvement-runner.mjs
    - packages/runtime-daemon/src/runtime-governed-improvement-runner.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the daemon governed-improvement runner
    exists
  - bridge conformance fails unless the runner sends
    `admit_governed_runtime_improvement_proposal` to the Rust bridge
  - JS unit coverage proves request shape, env configuration, unconfigured
    fail-closed behavior, and Rust rejection propagation
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-governed-improvement-runner.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: daemon callers can now submit proposal admission
    through a single Rust bridge facade without gaining a JS mutation path
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE review, rollback application, and live mutation
      commit path remain pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 98

```yaml
slice: 98
phase: 9-meta-improvement-proposal-path
objective: mount the daemon governed-improvement runner on
  `AgentgresRuntimeStateStore` as the single JS facade for future product/API
  proposal admission callers
owner_boundary:
  route_or_surface: daemon store dependency injection for governed improvement
    proposal admission
  authority_gate: store owns a runner handle only; it does not apply proposals or
    write accepted truth directly
  execution_backend: rust_governed_evolution through the mounted runner
  truth_path: callers must use the mounted runner to reach Rust bridge admission
  projection_path: later product/API and IDE review routes can reuse the same
    normalized admitted proposal records
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-governed-improvement-store.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the daemon store constructs
    `createGovernedImprovementRunnerFromEnv`
  - bridge conformance fails unless `this.governedImprovementRunner` is mounted
    on `AgentgresRuntimeStateStore`
  - JS unit coverage proves store dependency injection preserves the configured
    governed-improvement runner
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-governed-improvement-store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: product/API callers now have one daemon-owned
    runner handle for Rust proposal admission instead of creating ad hoc JS
    bridge paths
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE review, rollback application, and live mutation
      commit path remain pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 99

```yaml
slice: 99
phase: 9-meta-improvement-proposal-path
objective: expose a thread-scoped product/API route for governed runtime
  improvement proposal admission without adding any JS apply shortcut
owner_boundary:
  route_or_surface: `POST /v1/threads/{thread_id}/governed-improvement-proposals`
  authority_gate: route only submits proposal admission to the mounted Rust
    governed-improvement runner and returns `mutation_executed: false`
  execution_backend: rust_governed_evolution through the daemon runner and Rust
    bridge
  truth_path: Rust bridge admission remains the owner of proposal records,
    Agentgres refs, expected heads, and state roots
  projection_path: product/API callers can now submit proposal admission through
    the daemon; IDE review and application remain separate later surfaces
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs
    - packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the product/API route calls
    `store.admitGovernedImprovementProposal`
  - bridge conformance fails unless the governed-improvement surface delegates to
    `store.governedImprovementRunner.admitProposal`
  - bridge conformance fails unless the route test proves no governed-improvement
    apply shortcut exists
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs
    - node --test packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: API clients can now admit proposal records through
    the daemon facade, but no JS route can apply or commit the mutation
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - IDE review, rollback application, and live mutation commit path remain
      pending
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 100

```yaml
slice: 100
phase: 9-meta-improvement-proposal-path
objective: expose governed runtime-improvement proposal admission through stable
  SDK and IDE review client surfaces without adding a JS apply path
owner_boundary:
  route_or_surface: SDK `admitGovernedImprovementProposal` and IDE
    `createRuntimeGovernedImprovementControlRequest`
  authority_gate: clients can only submit the proposal envelope to the daemon
    route and mark `mutation_executed: false`
  execution_backend: rust_governed_evolution through the existing daemon route,
    runner, bridge, and Rust core admission
  truth_path: Rust governed-improvement admission remains the owner of proposal
    records, eval/verifier receipts, wallet approval refs, rollback refs,
    Agentgres operation refs, expected heads, and state roots
  projection_path: Hypervisor IDE/SDK can now compose review/admission requests
    against the stable route; rollback application and live mutation commit
    remain separate later authority surfaces
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core: []
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
    - packages/agent-sdk/src/index.ts
    - packages/agent-sdk/test/sdk.test.mjs
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts
    - packages/agent-ide/src/runtime/graph-runtime-types.ts
    - packages/agent-ide/src/index.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the SDK posts to
    `/v1/threads/{thread_id}/governed-improvement-proposals`
  - bridge conformance fails unless the IDE builder emits an admission-only
    request with `mutation_executed: false`
  - bridge conformance fails if the IDE governed-improvement client exposes an
    apply shortcut
verification:
  commands:
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts
    - npm run build --workspace=@ioi/agent-sdk
    - node --test --test-concurrency=1 --test-name-pattern "SDK admits governed improvement proposals" packages/agent-sdk/test/sdk.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  blocked_full_builds:
    - `npm run build --workspace=@ioi/agent-ide` remains blocked by
      pre-existing TypeScript errors in workflow computer-use replay/context
      lifecycle/signed replay/trajectory import files; the new governed
      improvement control-node test passes under `node --import tsx --test`
  replay_or_shadow_comparison: SDK and IDE clients now converge on the same
    daemon admission route; no client can directly apply or commit the proposal
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - Rollback application and live mutation commit path remain pending.
    - IDE review UI can now build the request but still needs a full review
      panel/flow.
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 101

```yaml
slice: 101
phase: 8-service-package-and-worker-package-invocation-path
objective: add a daemon-side worker/service package runner that calls the Rust
  package invocation admission bridge
owner_boundary:
  route_or_surface: daemon store dependency injection for worker/service package
    invocation admission
  authority_gate: runner only forwards package StepModule requests to the Rust
    bridge; missing wallet/daemon authority grants still fail in Rust
  execution_backend: rust_package_invocation through the command bridge
  truth_path: bridge result remains the owner of router admission, receipt
    binding, accepted receipt append, Agentgres admission, projection, artifact
    refs, payload refs, and authority grant refs
  projection_path: daemon callers can now depend on one mounted Rust package
    admission facade before product/SDK/IDE routes are added
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs
    - packages/runtime-daemon/src/runtime-worker-service-package-runner.test.mjs
    - packages/runtime-daemon/src/runtime-worker-service-package-store.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the daemon runner sends
    `admit_worker_service_package_invocation`
  - bridge conformance fails unless the runner fails closed without
    `IOI_WORKER_SERVICE_PACKAGE_COMMAND`
  - bridge conformance fails unless the runtime store mounts the injected
    worker/service package runner
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-worker-service-package-runner.test.mjs
    - node --test packages/runtime-daemon/src/runtime-worker-service-package-store.test.mjs
    - node --check packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: daemon package callers now share one
    fail-closed Rust bridge runner; no product route or JS admission shim can
    bypass Rust package admission
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE/SDK callers, and AIIP delivery surfaces still
      need to invoke the mounted runner for live package work
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 102

```yaml
slice: 102
phase: 8-service-package-and-worker-package-invocation-path
objective: expose a thread-scoped product/API route for worker/service package
  invocation admission through the mounted Rust package runner
owner_boundary:
  route_or_surface: daemon `POST /v1/threads/{thread_id}/worker-service-package-invocations`
  authority_gate: product/API route only normalizes the invocation envelope and
    calls the mounted runner; package authority grants, expected heads, receipt
    refs, and state roots remain validated by Rust
  execution_backend: rust_package_invocation through
    `RustWorkerServicePackageRunner`
  truth_path: Rust bridge result remains the source for StepModuleRouter
    admission, receipt binding, accepted receipt append, Agentgres admission,
    projection, refs, and authority grants
  projection_path: product/API callers receive the Rust projection/admission
    bundle; no JS apply/admit shortcut exists outside the mounted runner
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs
    - packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the store owns
    `admitWorkerServicePackageInvocation`
  - bridge conformance fails unless the product route posts to
    `worker-service-package-invocations` through the store facade
  - bridge conformance fails if the route exposes an apply shortcut or bypasses
    `workerServicePackageRunner.admitInvocation`
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs
    - node --test --test-name-pattern "worker/service package" packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - node --check packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs
    - node --check packages/runtime-daemon/src/runtime-route-handlers.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: product/API callers now converge on the same
    daemon-mounted Rust package admission runner and cannot create accepted
    package truth through a JS apply path
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - IDE/SDK callers and AIIP delivery surfaces still need to invoke the
      product route for live package work
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 103

```yaml
slice: 103
phase: 8-service-package-and-worker-package-invocation-path
objective: expose worker/service package invocation admission through stable SDK
  and IDE workflow-control clients
owner_boundary:
  route_or_surface: SDK `admitWorkerServicePackageInvocation` and IDE
    `createRuntimeWorkerServicePackageControlRequest`
  authority_gate: callers must provide the canonical package invocation with
    authority grant refs, result receipt refs, expected heads, and state roots;
    SDK/IDE add no JS execution or apply shortcut
  execution_backend: daemon product route to `rust_package_invocation`
  truth_path: SDK/IDE post to
    `/v1/threads/{thread_id}/worker-service-package-invocations`; Rust package
    admission remains the truth owner
  projection_path: Hypervisor IDE/SDK can now compose package admission requests
    that return the daemon/Rust projection bundle
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core: []
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
    - packages/agent-sdk/src/index.ts
    - packages/agent-sdk/test/sdk.test.mjs
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts
    - packages/agent-ide/src/runtime/graph-runtime-types.ts
    - packages/agent-ide/src/index.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the SDK posts to
    `worker-service-package-invocations`
  - bridge conformance fails unless the IDE builder emits an admission-only
    worker/service package request with no `/apply` shortcut
  - bridge conformance fails unless graph runtime request unions include the
    worker/service package control request
verification:
  commands:
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts
    - npm run build --workspace=@ioi/agent-sdk
    - node --test --test-concurrency=1 --test-name-pattern "SDK admits worker/service package" packages/agent-sdk/test/sdk.test.mjs
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: SDK and IDE clients converge on the product
    route added in Slice 102 and cannot mint accepted package truth directly
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - AIIP delivery surfaces and deeper live package execution UI still need to
      consume the same admission route/projection bundle
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 104

```yaml
slice: 104
phase: 7-ctee-private-workspace-module-path
objective: add a daemon-side cTEE Private Workspace runner that calls the Rust
  cTEE execution/admission bridge
owner_boundary:
  route_or_surface: daemon store dependency injection for Private Workspace
    cTEE execution admission
  authority_gate: runner only forwards cTEE StepModule invocations, node trust,
    and expected heads to Rust; plaintext custody, declassification, receipt,
    and Agentgres checks remain in Rust
  execution_backend: ctee_operator through the command bridge
  truth_path: bridge result remains the owner of cTEE receipt, StepModule result,
    receipt binding, accepted receipt append, Agentgres admission, projection,
    and evidence refs
  projection_path: daemon callers can now depend on one mounted Rust cTEE
    admission facade before product/SDK/IDE routes are added
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.test.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-store.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - cTEE conformance fails unless the daemon runner sends
    `execute_private_workspace_ctee_action`
  - cTEE conformance fails unless the runner fails closed without
    `IOI_CTEE_PRIVATE_WORKSPACE_COMMAND`
  - cTEE conformance fails unless the runtime store mounts the injected cTEE
    Private Workspace runner
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.test.mjs
    - node --test packages/runtime-daemon/src/runtime-ctee-private-workspace-store.test.mjs
    - node --check packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: daemon cTEE callers now share one fail-closed
    Rust bridge runner; no product route or JS cTEE admission shim can bypass
    Rust plaintext custody/admission checks
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE/SDK callers, and private workspace UI surfaces
      still need to invoke the mounted runner for live cTEE actions
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 105

```yaml
slice: 105
phase: 7-ctee-private-workspace-module-path
objective: expose a thread-scoped product/API route for cTEE Private Workspace
  action execution/admission through the mounted Rust cTEE runner
owner_boundary:
  route_or_surface: daemon `POST /v1/threads/{thread_id}/ctee-private-workspace-actions`
  authority_gate: product/API route only normalizes the action envelope and
    calls the mounted runner; plaintext custody, declassification, receipt
    binding, Agentgres heads, and projection checks remain validated by Rust
  execution_backend: ctee_operator through `RustCteePrivateWorkspaceRunner`
  truth_path: Rust bridge result remains the source for cTEE receipt,
    StepModule result, receipt binding, accepted receipt append, Agentgres
    admission, projection, and evidence refs
  projection_path: product/API callers receive the Rust cTEE
    projection/admission bundle; no JS apply shortcut exists
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - cTEE conformance fails unless the store owns
    `executeCteePrivateWorkspaceAction`
  - cTEE conformance fails unless the product route posts to
    `ctee-private-workspace-actions` through the store facade
  - cTEE conformance fails if the route exposes an apply shortcut or bypasses
    `cteePrivateWorkspaceRunner.executeAction`
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs
    - node --test --test-name-pattern "cTEE private workspace" packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - node --check packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs
    - node --check packages/runtime-daemon/src/runtime-route-handlers.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: product/API callers now converge on the same
    daemon-mounted Rust cTEE runner and cannot create cTEE accepted truth through
    a JS apply path
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - IDE/SDK callers and private workspace UI surfaces still need to invoke the
      product route for live cTEE actions
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 106

```yaml
slice: 106
phase: 7-ctee-private-workspace-module-path
objective: expose cTEE Private Workspace action admission through stable SDK
  and IDE workflow-control clients
owner_boundary:
  route_or_surface: SDK `executeCteePrivateWorkspaceAction` and IDE
    `createRuntimeCteePrivateWorkspaceControlRequest`
  authority_gate: callers must provide the cTEE StepModule invocation, node
    trust record, and expected heads; SDK/IDE add no JS execution or apply path
  execution_backend: daemon product route to `ctee_operator`
  truth_path: SDK/IDE post to
    `/v1/threads/{thread_id}/ctee-private-workspace-actions`; Rust cTEE
    execution/admission remains the truth owner
  projection_path: Hypervisor IDE/SDK can now compose cTEE action requests that
    return the daemon/Rust projection bundle
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon: []
  rust_core: []
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
    - packages/agent-sdk/src/index.ts
    - packages/agent-sdk/test/sdk.test.mjs
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts
    - packages/agent-ide/src/runtime/graph-runtime-types.ts
    - packages/agent-ide/src/index.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - cTEE conformance fails unless the SDK posts to
    `ctee-private-workspace-actions`
  - cTEE conformance fails unless the IDE builder emits an admission-only cTEE
    request with no `/apply` shortcut
  - cTEE conformance fails unless graph runtime request unions include the cTEE
    private workspace control request
verification:
  commands:
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts
    - npm run build --workspace=@ioi/agent-sdk
    - node --test --test-concurrency=1 --test-name-pattern "SDK executes cTEE private workspace" packages/agent-sdk/test/sdk.test.mjs
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: SDK and IDE clients converge on the product
    route added in Slice 105 and cannot mint accepted cTEE truth directly
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - deeper private workspace UI/replay surfaces still need to consume the same
      admission route/projection bundle
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 107

```yaml
slice: 107
phase: 11-authoritative-js-facade-retirement
objective: expose L1 settlement admission through the Rust command bridge while
  preserving trigger-required settlement semantics
owner_boundary:
  route_or_surface: Rust command bridge `admit_l1_settlement_attempt`
  authority_gate: `L1SettlementTriggerGuard` rejects attempts without explicit
    trigger refs and settlement receipt refs
  execution_backend: l1_settlement_guard through the command bridge
  truth_path: bridge result is a Rust admission record only; no product route or
    JS settlement write exists in this slice
  projection_path: downstream daemon/product surfaces can consume the admission
    record later without treating IOI L1 as default runtime settlement
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
  - bridge conformance fails unless `admit_l1_settlement_attempt` is dispatched
    through `L1SettlementTriggerGuard`
  - bridge conformance fails unless the Rust bridge test proves a triggered
    settlement attempt is admitted
  - negative conformance remains responsible for proving missing-trigger
    attempts fail closed
verification:
  commands:
    - cargo test -p ioi-node bridge_admits_l1_settlement_attempt_through_rust_core
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: L1 settlement is now bridge-admissible only when
    Rust trigger guard accepts it; no JS product route can bypass this bridge
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product settlement surfaces still need to call the Rust bridge before any
      sparse public/economic commitment can be attempted
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 108

```yaml
slice: 108
phase: 11-authoritative-js-facade-retirement
objective: add a daemon-side L1 settlement runner that calls the Rust settlement
  trigger-guard admission bridge
owner_boundary:
  route_or_surface: daemon store dependency injection for L1 settlement
    admission
  authority_gate: runner only forwards settlement attempts to Rust; trigger refs
    and settlement receipt refs remain validated by `L1SettlementTriggerGuard`
  execution_backend: l1_settlement_guard through the command bridge
  truth_path: bridge result remains the owner of the L1 settlement admission
    record and admission hash
  projection_path: daemon callers can depend on one mounted Rust L1 settlement
    admission facade before product/SDK/IDE routes are added
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-runner.test.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-store.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the daemon runner sends
    `admit_l1_settlement_attempt`
  - bridge conformance fails unless the runner fails closed without
    `IOI_L1_SETTLEMENT_COMMAND`
  - bridge conformance fails unless the runtime store mounts the injected L1
    settlement runner
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-l1-settlement-runner.test.mjs
    - node --test packages/runtime-daemon/src/runtime-l1-settlement-store.test.mjs
    - node --check packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: daemon settlement callers now share one
    fail-closed Rust bridge runner; no product route or JS settlement shim can
    bypass Rust trigger checks
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - product daemon routes, IDE/SDK callers, and sparse settlement UI surfaces
      still need to invoke the mounted runner for triggered settlement attempts
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 109

```yaml
slice: 109
phase: 11-authoritative-js-facade-retirement
objective: expose a thread-scoped product/API route for L1 settlement admission
  through the mounted Rust trigger-guard runner
owner_boundary:
  route_or_surface: daemon `POST /v1/threads/{thread_id}/l1-settlement-attempts`
  authority_gate: product/API route only normalizes the settlement-attempt
    envelope and calls the mounted runner; trigger refs and settlement receipt
    refs remain validated by Rust
  execution_backend: l1_settlement_guard through `RustL1SettlementRunner`
  truth_path: Rust bridge result remains the source for the L1 settlement
    admission record and admission hash
  projection_path: product/API callers receive the Rust admission bundle; no JS
    apply/settle shortcut exists
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.mjs
    - packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs
  rust_core: []
  ide: []
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the store owns
    `admitL1SettlementAttempt`
  - bridge conformance fails unless the product route posts to
    `l1-settlement-attempts` through the store facade
  - bridge conformance fails if the route exposes an apply shortcut or bypasses
    `l1SettlementRunner.admitAttempt`
verification:
  commands:
    - node --test packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs
    - node --test --test-name-pattern "L1 settlement" packages/runtime-daemon/src/runtime-route-handlers.test.mjs
    - node --check packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs
    - node --check packages/runtime-daemon/src/runtime-route-handlers.mjs
    - node --check packages/runtime-daemon/src/index.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: product/API callers now converge on the same
    daemon-mounted Rust L1 settlement runner and cannot attempt settlement
    through a JS apply path
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - IDE/SDK callers and sparse settlement UI surfaces still need to invoke the
      product route for triggered settlement attempts
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 110

```yaml
slice: 110
phase: 11-authoritative-js-facade-retirement
objective: expose SDK and IDE L1 settlement admission clients that consume the
  daemon product route without creating accepted truth directly
owner_boundary:
  route_or_surface: SDK `admitL1SettlementAttempt` and IDE
    `createRuntimeL1SettlementControlRequest`
  authority_gate: clients only package trigger-required settlement attempts for
    the daemon route; Rust remains responsible for trigger and settlement
    receipt validation
  execution_backend: l1_settlement_guard through the daemon-mounted
    `RustL1SettlementRunner`
  truth_path: SDK/IDE clients receive the Rust admission bundle and cannot
    append accepted settlement truth
  projection_path: workflow control nodes emit admission-only request bodies for
    Hypervisor IDE composition and replay
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
    - packages/agent-sdk/test/sdk.test.mjs
  ide:
    - packages/agent-ide/src/index.ts
    - packages/agent-ide/src/runtime/graph-runtime-types.ts
    - packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the SDK exposes
    `admitL1SettlementAttempt`
  - bridge conformance fails unless IDE control nodes target
    `l1-settlement-attempts`
  - bridge conformance fails if IDE settlement controls expose apply shortcuts,
    default runtime settlement, or direct truth writes
verification:
  commands:
    - npm run build --workspace=@ioi/agent-sdk
    - node --test --test-name-pattern "SDK admits L1 settlement" packages/agent-sdk/test/sdk.test.mjs
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: SDK and IDE callers now converge on the same
    daemon L1 settlement route and cannot mint accepted settlement truth or
    attempt default L1 settlement locally
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - sparse settlement UI/replay panels still need deeper product integration,
      but authoritative client admission now routes through the daemon API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 111

```yaml
slice: 111
phase: 12-full-conformance-suite
objective: restore the Hypervisor IDE package build gate for migrated runtime
  protocol-client surfaces
owner_boundary:
  route_or_surface: IDE runtime protocol-client helpers and tests for
    cTEE, worker/service package, L1 settlement, replay, context lifecycle, and
    signed replay/audit panels
  authority_gate: no authority semantics changed; this slice only removes
    TypeScript target/nullability blockers so the IDE facade can be package-build
    verified
  execution_backend: unchanged
  truth_path: unchanged; migrated control nodes remain admission-only clients of
    daemon routes
  projection_path: IDE projection/client helpers compile under the current
    package target without relying on unconfigured ES2022 APIs
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-computer-use-replay-timeline.ts
    - packages/agent-ide/src/runtime/workflow-context-lifecycle-panel.ts
    - packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts
    - packages/agent-ide/src/runtime/workflow-trajectory-import-audit.ts
    - packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts
  tests: []
conformance_checks:
  - IDE package build fails if migrated protocol-client tests or projection
    helpers drift outside the current TypeScript target/nullability contract
verification:
  commands:
    - npm run build --workspace=@ioi/agent-ide
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: no runtime behavior changed; this slice proves
    the IDE migrated client/projection surface can build and test as a stable
    facade over daemon-owned admission routes
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - broader IDE product integration for sparse L1 settlement and replay panels
      remains outside this build-gate cleanup
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 112

```yaml
slice: 112
phase: 11-authoritative-js-facade-retirement
objective: expose a CLI L1 settlement admission client that posts to the daemon
  product route without minting accepted truth
owner_boundary:
  route_or_surface: CLI `runtime l1-settlement admit`
  authority_gate: CLI only loads a settlement-attempt JSON object and submits it
    to the daemon route; Rust remains responsible for trigger and settlement
    receipt validation
  execution_backend: l1_settlement_guard through the daemon-mounted
    `RustL1SettlementRunner`
  truth_path: CLI receives the daemon/Rust admission bundle and cannot append
    accepted settlement truth
  projection_path: not changed; CLI is a non-authoritative protocol adapter
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  cli:
    - crates/cli/src/main.rs
    - crates/cli/src/commands/mod.rs
    - crates/cli/src/commands/runtime.rs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the CLI exposes the runtime L1 settlement
    admission command
  - bridge conformance fails unless the CLI command targets
    `/v1/threads/{thread_id}/l1-settlement-attempts`
  - bridge conformance fails if the CLI command can mint
    `settlement_admitted: true` locally
verification:
  commands:
    - cargo fmt -- crates/cli/src/main.rs crates/cli/src/commands/mod.rs crates/cli/src/commands/runtime.rs
    - cargo test -p ioi-cli --bin cli runtime::tests
    - cargo check -p ioi-cli --bin cli
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: CLI, SDK, and IDE L1 settlement callers now
    converge on the same daemon admission route without local settlement apply
    or accepted-truth shortcuts
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - CLI clients for worker/service package, cTEE, and governed improvement
      admissions still need equivalent daemon-route adapters
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 113

```yaml
slice: 113
phase: 11-authoritative-js-facade-retirement
objective: expose CLI admission clients for the remaining migrated daemon route
  families so CLI, SDK, and IDE all consume stable daemon protocol APIs
owner_boundary:
  route_or_surface: CLI `runtime worker-service-package admit`,
    `runtime ctee-private-workspace execute`, and
    `runtime governed-improvement admit`
  authority_gate: CLI only loads JSON payload objects and submits them to the
    daemon route; Rust remains responsible for package admission, cTEE custody,
    governed proposal validation, receipt binding, and Agentgres admission
  execution_backend: daemon-mounted Rust worker/service package, cTEE, and
    governed improvement runners
  truth_path: CLI receives daemon/Rust admission bundles and cannot append
    accepted package, cTEE, or governed-improvement truth
  projection_path: not changed; CLI is a non-authoritative protocol adapter
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  cli:
    - crates/cli/src/commands/runtime.rs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails unless the CLI targets the worker/service package,
    cTEE Private Workspace, and governed improvement daemon routes
  - bridge conformance fails unless each CLI body is an admission-only
    `source: cli_client` envelope around the requested payload
  - bridge conformance fails if the CLI can locally mint accepted package,
    cTEE, governed-improvement, or mutation truth flags
verification:
  commands:
    - cargo fmt -- crates/cli/src/main.rs crates/cli/src/commands/mod.rs crates/cli/src/commands/runtime.rs
    - cargo test -p ioi-cli --bin cli runtime::tests
    - cargo check -p ioi-cli --bin cli
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: CLI, SDK, and IDE callers for worker/service
    package, cTEE Private Workspace, governed improvement, and L1 settlement
    now converge on the same daemon admission routes without local apply or
    accepted-truth shortcuts
cleanup:
  legacy_paths_removed: false
  compatibility_shims_remaining:
    - deeper package execution UI, private workspace replay panels, governed
      review UI, rollback application, and live mutation commit path remain
      outside this CLI protocol-adapter slice
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 114

```yaml
slice: 114
phase: 10-authoritative-js-facade-retirement
objective: retire the unused legacy run-event read alias from the daemon runtime
  read surface
owner_boundary:
  route_or_surface: `RuntimeRunReadSurface` and daemon store read facade
  authority_gate: unchanged; this slice removes a compatibility read alias and
    does not alter authority decisions or mutation paths
  execution_backend: unchanged
  truth_path: callers must use canonical replay/projection reads
    (`replayFromCanonicalState`, `traceFromCanonicalState`, and
    `canonicalProjection`) instead of the legacy events alias
  projection_path: canonical replay remains backed by runtime event streams and
    Agentgres projection watermarks
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/runtime-run-read-surface.mjs
  tests:
    - packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if `legacyEventsForRun` reappears on the
    daemon runtime store or run-read surface
  - focused read-surface coverage proves canonical replay remains available
verification:
  commands:
    - node --check packages/runtime-daemon/src/index.mjs packages/runtime-daemon/src/runtime-run-read-surface.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: canonical replay still returns from
    `eventsForRun`; this slice removes only the stale compatibility alias over
    run-local event arrays
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader runtime event envelope/projection ownership is still JS-shaped
      until Rust projection records become the stable SDK/IDE/CLI read API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 115

```yaml
slice: 115
phase: 10-authoritative-js-facade-retirement
objective: retire the internal `legacyModelList` compatibility facade name from
  model-mounting reads while preserving the public model-list API
owner_boundary:
  route_or_surface: model-mounting read model, read projection facade,
    `ModelMountingState`, and daemon `listModels`
  authority_gate: unchanged; this slice renames a read projection facade and
    does not alter provider execution, authority, receipt binding, or model
    selection semantics
  execution_backend: unchanged
  truth_path: public callers still use `listModels`; internally the read path
    now names the projection as `runtimeModelCatalogList`
  projection_path: runtime model catalog projection still derives from
    product-safe model artifacts
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
    - packages/runtime-daemon/src/model-mounting.mjs
    - packages/runtime-daemon/src/model-mounting/read-model.mjs
    - packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/product-defaults.test.mjs
    - packages/runtime-daemon/src/model-mounting/read-model.test.mjs
    - packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails if the daemon/model-mounting implementation
    reintroduces `legacyModelList`
  - bridge conformance requires the runtime model catalog projection name across
    the store, facade, read model, and focused tests
verification:
  commands:
    - node --check packages/runtime-daemon/src/index.mjs packages/runtime-daemon/src/model-mounting.mjs packages/runtime-daemon/src/model-mounting/read-model.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs packages/runtime-daemon/src/model-mounting/product-defaults.test.mjs packages/runtime-daemon/src/model-mounting/read-model.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/read-model.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/product-defaults.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; behavior is preserved through the
    public daemon `listModels` read API while the internal compatibility name is
    retired
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader model-mounting JS store/provider demotion still remains until all
      provider transports move behind Rust `model_mount`/`workload_client`
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 116

```yaml
slice: 116
phase: 10-authoritative-js-facade-retirement
objective: retire legacy runtime-event payload id/type aliases from daemon
  projections and SDK event typing
owner_boundary:
  route_or_surface: runtime event payload projection and SDK runtime event
    message mapping
  authority_gate: unchanged; this slice removes duplicate compatibility payload
    aliases and keeps canonical envelope metadata as the SDK/IDE/CLI read
    contract
  execution_backend: unchanged
  truth_path: callers must use canonical `event_id`, `event_kind`,
    `event_stream_id`, and cursor sequence metadata from the runtime event
    envelope instead of payload-level legacy run-event ids or types
  projection_path: daemon event payload summaries still carry run/agent/summary
    projection data, while SDK typed messages derive from canonical
    `event_kind`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-event-payloads.mjs
  sdk:
    - packages/agent-sdk/src/runtime-events.ts
    - packages/agent-sdk/src/substrate-client.ts
  tests:
    - packages/runtime-daemon/src/runtime-event-payloads.test.mjs
    - packages/runtime-daemon/src/runtime-event-envelopes.test.mjs
    - packages/agent-sdk/test/sdk.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if daemon runtime event payload summaries
    reintroduce legacy event id/type aliases
  - compositor conformance fails if the SDK mock/runtime-event path emits or
    reads the legacy type alias instead of canonical `event_kind`
  - focused daemon and SDK coverage prove payloads no longer expose the retired
    aliases
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-event-payloads.mjs packages/runtime-daemon/src/runtime-event-payloads.test.mjs packages/runtime-daemon/src/runtime-event-envelopes.test.mjs packages/agent-sdk/test/sdk.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - npm run build --workspace=@ioi/agent-sdk
    - node --test packages/runtime-daemon/src/runtime-event-payloads.test.mjs packages/runtime-daemon/src/runtime-event-envelopes.test.mjs
    - node --test --test-name-pattern "Thread and Turn wrappers project canonical daemon events" packages/agent-sdk/test/sdk.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; canonical envelope metadata is
    unchanged while duplicate payload aliases are removed from daemon and SDK
    projections
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader runtime event envelope normalization remains JS-shaped until Rust
      projection records become the stable SDK/IDE/CLI read API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 117

```yaml
slice: 117
phase: 10-authoritative-js-facade-retirement
objective: delete dead SDK runtime-event mock envelope helpers and their
  noncanonical cursor fallback
owner_boundary:
  route_or_surface: SDK runtime event projection module
  authority_gate: unchanged; this slice removes unused SDK test/mock helper
    exports and does not alter daemon event production or authority decisions
  execution_backend: unchanged
  truth_path: SDK event streaming now has no helper that accepts a non-schema
    `event.id` cursor beside canonical runtime `event_id`
  projection_path: `runtimeThreadEventFromEnvelope` remains the only SDK helper
    in this module for projecting canonical runtime event envelopes into typed
    thread events
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  sdk:
    - packages/agent-sdk/src/runtime-events.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if the SDK runtime-event module reintroduces
    dead mock envelope builders or cursor helpers
  - compositor conformance fails if the SDK runtime-event module reintroduces
    the noncanonical `event.id` cursor fallback beside `event_id`
verification:
  commands:
    - npm run build --workspace=@ioi/agent-sdk
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; behavior is unchanged for live
    daemon event streaming because the removed helpers had no repo callers
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader runtime event envelope normalization remains JS-shaped until Rust
      projection records become the stable SDK/IDE/CLI read API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 118

```yaml
slice: 118
phase: 10-authoritative-js-facade-retirement
objective: retire daemon runtime-event envelope output aliases and route SSE
  cursors through canonical `event_id`
owner_boundary:
  route_or_surface: daemon runtime event normalizer, SSE writer, and replay
    cursor lookup
  authority_gate: unchanged; this slice removes duplicate projection aliases and
    keeps canonical envelope metadata as the read contract
  execution_backend: unchanged
  truth_path: runtime event replay and SSE cursors now use canonical
    `event_id`; stream sequence numbers remain a numeric cursor fallback
  projection_path: normalized runtime event records keep `payload_summary` for
    current projection consumers but no longer emit duplicate top-level `id`,
    `event`, or `timestamp_ms` aliases beside `event_id`, `event_kind`, and
    `created_at`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-event-envelopes.mjs
    - packages/runtime-daemon/src/runtime-http-utils.mjs
    - packages/runtime-daemon/src/threads/thread-replay.mjs
  tests:
    - packages/runtime-daemon/src/runtime-event-envelopes.test.mjs
    - packages/runtime-daemon/src/runtime-http-utils.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if normalized runtime event envelopes
    reintroduce `id`, `event`, or `timestamp_ms` output aliases
  - compositor conformance fails if SSE event IDs or replay cursor lookup use
    the retired top-level `id` alias instead of canonical `event_id`
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-event-envelopes.mjs packages/runtime-daemon/src/runtime-event-envelopes.test.mjs packages/runtime-daemon/src/runtime-http-utils.mjs packages/runtime-daemon/src/runtime-http-utils.test.mjs packages/runtime-daemon/src/threads/thread-replay.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-event-envelopes.test.mjs packages/runtime-daemon/src/runtime-http-utils.test.mjs packages/runtime-daemon/src/threads/thread-replay.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: replay behavior still accepts canonical
    `event_id` and numeric sequence cursors; only the retired top-level alias
    cursor path is removed
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - `payload_summary` remains during JS-shaped projection demotion until Rust
      projection records become the stable SDK/IDE/CLI read API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 119

```yaml
slice: 119
phase: 10-authoritative-js-facade-retirement
objective: retire MCP serve-result fallback to runtime event `id` aliases
owner_boundary:
  route_or_surface: runtime MCP serve tool-result projection
  authority_gate: unchanged; MCP serve result shaping remains non-authoritative
    projection over daemon runtime event records
  execution_backend: unchanged
  truth_path: MCP structured results now report only canonical runtime
    `event_id` values from invocation events and ignore retired top-level
    `event.id` aliases
  projection_path: MCP clients receive the same tool result summary, receipt
    refs, policy refs, artifact refs, and canonical runtime event id when one
    exists
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-mcp-helpers.mjs
  tests:
    - packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if MCP serve tool-result projection falls back
    from canonical `event_id` to the retired `event.id` alias
  - focused MCP helper coverage proves canonical `event_id` is preserved and
    retired `event.id` is ignored
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-mcp-helpers.mjs packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; only duplicate event-id fallback
    shaping is removed
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader MCP/client event projection can continue to demote JS-shaped
      helpers as Rust projection records become the stable read API
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 120

```yaml
slice: 120
phase: 10-authoritative-js-facade-retirement
objective: retire IDE terminal coding-loop run-launch fallback to runtime event
  `id` aliases
owner_boundary:
  route_or_surface: Hypervisor IDE terminal coding-loop run launch telemetry
    materialization
  authority_gate: unchanged; IDE run launch still invokes daemon coding-tool
    surfaces and only projects returned runtime events for UI telemetry
  execution_backend: unchanged
  truth_path: IDE launch telemetry now materializes runtime thread events only
    when tool results expose canonical `event_id`; retired nested `event.id`
    and root `eventId` aliases are ignored
  projection_path: run history keeps canonical runtime thread events when
    available and omits telemetry materialization for legacy-only event ids
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts
  tests:
    - packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if terminal coding-loop run launch accepts
    retired runtime event id aliases while materializing telemetry
  - focused IDE launch coverage proves legacy-only event ids do not produce
    runtime thread telemetry events
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; only duplicate event-id fallback
    materialization is removed
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader IDE runtime panels still need a shared canonical event identity
      adapter so raw daemon records cannot use retired `id` aliases while
      projected IDE event objects can keep their typed `id` identity
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 121

```yaml
slice: 121
phase: 10-authoritative-js-facade-retirement
objective: retire IDE computer-use replay timeline fallback to runtime event
  `id` aliases
owner_boundary:
  route_or_surface: Hypervisor IDE computer-use replay timeline
  authority_gate: unchanged; the timeline remains a read-only projection over
    daemon/Rust computer-use runtime records
  execution_backend: unchanged
  truth_path: replay frames now preserve event identifiers only from canonical
    `event_id` fields and ignore retired raw `id` aliases
  projection_path: computer-use replay still renders artifact refs, redaction
    metadata, policy refs, and lane/frame summaries without accepting duplicate
    event-id aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-computer-use-replay-timeline.ts
  tests:
    - scripts/lib/workflow-computer-use-replay-timeline-proof.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if the computer-use replay timeline accepts
    retired `id`/`eventId` event-id aliases
  - proof coverage verifies canonical computer-use events retain frame IDs and
    legacy-only raw `id` events produce null frame event IDs
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs scripts/lib/workflow-computer-use-replay-timeline-proof.mjs
    - node --import tsx scripts/lib/workflow-computer-use-replay-timeline-proof.mjs /tmp/workflow-computer-use-replay-timeline-proof.json
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: proof script checks canonical timeline output
    and an explicit legacy-only alias canary
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - mixed raw/projected IDE panels still need a shared event identity adapter
      before their typed projected `id` fields can be distinguished from raw
      retired daemon aliases
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 122

```yaml
slice: 122
phase: 10-authoritative-js-facade-retirement
objective: centralize mixed IDE runtime event identity handling and retire raw
  `id`/`event` alias fallbacks
owner_boundary:
  route_or_surface: Hypervisor IDE runtime projection panels that accept both
    raw daemon records and projected IDE runtime events
  authority_gate: unchanged; panels remain read-only compositor/projection
    surfaces
  execution_backend: unchanged
  truth_path: raw daemon records are read through canonical `event_id` and
    `event_kind`; projected IDE events may keep their typed `id`/`eventKind`
    identity only after shape validation
  projection_path: goal verification, policy lease, receipt-first tool
    timeline, and delegation matrix panels share one event identity adapter
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-event-identity.ts
    - packages/agent-ide/src/runtime/workflow-runtime-goal-verification-panel.ts
    - packages/agent-ide/src/runtime/workflow-runtime-policy-lease-panel.ts
    - packages/agent-ide/src/runtime/workflow-runtime-receipt-first-tool-timeline.ts
    - packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts
  tests:
    - packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if mixed IDE panels reintroduce raw
    `event_id`/`eventId`/`id` or `eventKind`/`event_kind`/`event` fallback
    chains
  - focused helper coverage proves canonical raw fields are accepted, raw
    retired aliases are ignored, and typed projected IDE event identity is
    preserved only after projected-shape validation
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: helper tests cover raw canonical records,
    raw legacy aliases, and projected IDE event records
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - typed IDE event `id` remains as a projected UI identity, not a raw daemon
      event alias; remaining typed-only panel helpers can be migrated to this
      adapter opportunistically
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 123

```yaml
slice: 123
phase: 10-authoritative-js-facade-retirement
objective: move typed IDE runtime panels onto the shared event identity helper
owner_boundary:
  route_or_surface: Hypervisor IDE typed runtime projection panels
  authority_gate: unchanged; panels remain read-only compositor/proof surfaces
  execution_backend: unchanged
  truth_path: typed projected IDE event IDs are resolved only through the
    shared helper, which also accepts canonical raw `event_id` when present
  projection_path: workspace trust, hunk-decision receipts, signed replay,
    context lifecycle, and worker contribution trace panels keep their existing
    projection rows while dropping local `event_id`/`id` wrappers
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-workspace-trust-gate.ts
    - packages/agent-ide/src/runtime/workflow-hunk-decision-receipt-panel.ts
    - packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts
    - packages/agent-ide/src/runtime/workflow-context-lifecycle-panel.ts
    - packages/agent-ide/src/runtime/workflow-worker-contribution-trace.ts
  tests:
    - packages/agent-ide/src/runtime/workflow-workspace-trust-gate.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance fails if typed IDE runtime panels reintroduce local
    `event_id`/`id` fallback wrappers instead of the shared helper
  - focused helper/workspace-trust tests continue to pass with typed projected
    event IDs
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-workspace-trust-gate.test.ts
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: helper tests exercise canonical raw records,
    raw legacy aliases, and typed projected IDE event records; workspace trust
    coverage exercises one migrated typed panel end to end
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - deeper runtime projection internals still use typed `event.id` as the
      projected UI identity; that is distinct from raw daemon `id` aliases
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 124

```yaml
slice: 124
phase: 10-authoritative-js-facade-retirement
objective: retire worker/service package and cTEE admission response camelCase aliases
owner_boundary:
  route_or_surface:
    - runtime worker/service package admission response
    - runtime cTEE Private Workspace admission response
  authority_gate: unchanged; responses remain daemon-exposed views over Rust
    runner admission outputs
  execution_backend: unchanged; worker/service packages route through the Rust
    package invocation bridge, and cTEE actions route through the Rust cTEE
    bridge
  truth_path: canonical snake_case fields only; duplicate camelCase response
    wrappers no longer advertise or mirror accepted admission truth
  projection_path: unchanged; response records still carry canonical admission,
    receipt, Agentgres, and projection refs
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
  tests:
    - packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs
    - packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails if worker/service package admission responses or
    SDK result types reintroduce camelCase response aliases
  - cTEE conformance fails if cTEE Private Workspace admission responses or SDK
    result types reintroduce camelCase response aliases
  - focused daemon tests assert the retired alias keys are absent from emitted
    response objects
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs
    - npm run build --workspace=@ioi/agent-sdk
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:ctee
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare canonical admitted
    response fields against the Rust runner stub while negative alias assertions
    prove the duplicate wrappers are not emitted
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request builders still accept camelCase UI/client input convenience fields
      in adjacent IDE surfaces; this slice retires admitted response aliases only
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 125

```yaml
slice: 125
phase: 10-authoritative-js-facade-retirement
objective: retire governed-improvement and L1 settlement admission response camelCase aliases
owner_boundary:
  route_or_surface:
    - runtime governed-improvement proposal admission response
    - runtime L1 settlement admission response
  authority_gate: unchanged; governed proposals remain Rust-admitted and L1
    settlement attempts remain Rust trigger-guarded
  execution_backend: unchanged; both surfaces call their mounted Rust bridge
    runners through the daemon-owned store
  truth_path: canonical snake_case fields only; duplicate camelCase response
    wrappers no longer mirror proposal or settlement admission truth
  projection_path: unchanged; responses still carry canonical admission hashes,
    Agentgres refs, state roots, trigger refs, and records
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs
  sdk:
    - packages/agent-sdk/src/substrate-client.ts
  tests:
    - packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs
    - packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails if governed-improvement admission responses or SDK
    result types reintroduce camelCase response aliases
  - bridge conformance fails if L1 settlement admission responses or SDK result
    types reintroduce camelCase response aliases
  - focused daemon tests assert the retired alias keys are absent from emitted
    response objects
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs
    - npm run build --workspace=@ioi/agent-sdk
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare canonical admitted
    response fields against the Rust runner stubs while negative alias assertions
    prove the duplicate wrappers are not emitted
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request builders still accept camelCase UI/client input convenience fields
      in adjacent IDE surfaces; this slice retires admitted response aliases only
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 126

```yaml
slice: 126
phase: 10-authoritative-js-facade-retirement
objective: retire the coding-tool result `routerAdmission` response alias
owner_boundary:
  route_or_surface: runtime coding-tool invocation result projection
  authority_gate: unchanged; coding-tool execution remains Rust workload live
    and StepModuleRouter-admitted
  execution_backend: unchanged; migrated coding tools continue through the Rust
    command bridge and live workload runner
  truth_path: canonical `router_admission` only; the duplicate camelCase
    `routerAdmission` wrapper no longer mirrors router admission truth
  projection_path: unchanged; established public coding-tool result fields remain
    intact while router admission uses the canonical Rust field name
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
  tests:
    - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance fails if Rust live coding-tool results reintroduce the
    `routerAdmission` response alias
  - focused daemon test asserts `router_admission` is present and
    `routerAdmission` is absent
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: live-path daemon test stubs a Rust
    StepModuleRouter admission and verifies only the canonical
    `router_admission` field is emitted
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader coding-tool result payloads still use established public
      camelCase result fields; this slice retires only the duplicate router
      admission truth wrapper
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 127

```yaml
slice: 127
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount invocation receipt-binding detail fields
owner_boundary:
  route_or_surface: model-mount invocation and stream-completion receipt
    persistence guard
  authority_gate: unchanged; invocation receipts still require Rust
    receipt_binder output and Rust Agentgres admission before JS store
    persistence
  execution_backend: unchanged; migrated model-mount invocations continue
    through the Rust model_mount bridge and daemon-owned receipt store
  truth_path: canonical snake_case receipt-binding, accepted-receipt append,
    StepModule, router-admission, Agentgres-admission, and projection fields
    only; legacy camelCase `modelMount*` binding detail keys no longer satisfy
    the accepted receipt write guard
  projection_path: unchanged; receipt details still embed the Rust
    receipt_binder result, StepModule invocation/result, Agentgres admission,
    and projection record, but under canonical protocol field names
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge and receipts conformance now require canonical snake_case
    model-mount receipt-binding fields
  - receipts conformance fails if the model-mount invocation receipt producer
    or receipt-write guard reintroduces the retired camelCase `modelMount*`
    binding detail keys
  - focused store tests prove a legacy camel-only receipt detail object fails
    closed instead of satisfying the accepted receipt append guard
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust
    receipt_binder/Agentgres binding output against the persisted receipt
    detail fields while negative assertions prove retired camelCase binding
    keys are absent or rejected
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - adjacent model-mount admission/provider detail metadata still uses
      established public camelCase receipt-detail field names; this slice
      retires the accepted receipt-binding and Agentgres guard field family
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 128

```yaml
slice: 128
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount admission receipt-detail metadata
owner_boundary:
  route_or_surface: model-mount invocation, provider-execution, and
    provider-result admission metadata embedded in accepted receipt details
  authority_gate: unchanged; Rust model_mount admission still owns the
    admission records before accepted receipt persistence
  execution_backend: unchanged; migrated model-mount provider execution and
    observation paths continue through the mounted Rust bridge
  truth_path: canonical snake_case admission metadata only; duplicate
    camelCase `modelMount*Admission*` and `modelMountProviderExecution*`
    receipt-detail keys no longer mirror admitted Rust records
  projection_path: unchanged; accepted receipts still embed invocation
    admission, provider-execution admission, and provider-result admission
    records under canonical protocol field names
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires canonical snake_case model-mount admission
    receipt-detail fields
  - bridge conformance fails if the model-mount invocation receipt producer
    reintroduces camelCase admission/provider-execution detail keys
  - focused daemon tests assert retired camelCase admission detail keys are
    absent from invocation and stream-start receipts
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust
    invocation/provider admission records against persisted receipt details
    while negative assertions prove retired camelCase admission keys are absent
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader non-authoritative model-mount route/input helpers still accept
      camelCase client convenience fields; this slice removes duplicate
      admitted receipt-detail metadata only
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 129

```yaml
slice: 129
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount route-decision receipt-detail metadata
owner_boundary:
  route_or_surface: model-mount route-selection receipts and downstream
    invocation/provider-execution admission requests
  authority_gate: unchanged; route-selection receipt creation still requires
    Rust model_mount route-decision admission before provider invocation
  execution_backend: unchanged; migrated model-mount provider execution and
    observation paths continue through the mounted Rust bridge
  truth_path: canonical snake_case route-decision metadata only; duplicate
    camelCase `modelMountRouteDecision*` receipt-detail keys no longer mirror
    admitted Rust route-decision records or feed downstream admission requests
  projection_path: unchanged; route-selection receipts still embed the
    Rust-admitted route-decision record under canonical protocol field names
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/routes.mjs
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/routes.test.mjs
    - packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires canonical snake_case route-decision
    receipt-detail fields
  - bridge conformance fails if route-selection receipts or downstream
    model-invocation admission request builders reintroduce the retired
    camelCase route-decision detail key
  - focused daemon tests assert retired camelCase route-decision detail keys
    are absent from route-selection receipts
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/routes.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust
    route-decision admission output against persisted route-selection receipt
    details while negative assertions prove retired camelCase route-decision
    keys are absent
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader non-authoritative model-mount route/input helpers still accept
      camelCase client convenience fields; this slice removes duplicate
      admitted route-decision receipt-detail metadata only
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 130

```yaml
slice: 130
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount instance-lifecycle binding metadata
owner_boundary:
  route_or_surface: migrated local-provider model-instance state records and
    lifecycle receipts for load, unload, idle-evict, and supersede transitions
  authority_gate: unchanged; migrated local-provider instance transitions still
    require Rust `plan_model_mount_instance_lifecycle` output before JS state or
    lifecycle receipt persistence
  execution_backend: unchanged; JS still supervises local provider process/state
    records while Rust model_mount owns transition planning and hashes
  truth_path: canonical snake_case instance-lifecycle binding metadata only;
    duplicate camelCase `modelMountInstanceLifecycle*` state/receipt fields no
    longer mirror Rust-planned lifecycle records
  projection_path: unchanged; model-instance records and lifecycle receipts
    continue to project from the same persisted store with canonical binding
    fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs
    - packages/runtime-daemon/src/model-mounting/loaded-instances.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs
    - packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires canonical snake_case instance-lifecycle fields
    from the Rust-planned lifecycle helper
  - receipt conformance fails if model-instance state or lifecycle receipt
    guards reintroduce retired camelCase instance-lifecycle binding keys
  - focused daemon tests assert migrated load/unload/evict/supersede state and
    receipt records use canonical instance-lifecycle binding metadata
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs packages/runtime-daemon/src/model-mounting/state-persistence.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust-planned
    instance lifecycle hashes/evidence against persisted state and lifecycle
    receipt fields while conformance rejects retired camelCase binding keys
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - provider lifecycle and broader non-authoritative local-provider state
      metadata still use older convenience field names; this slice removes only
      duplicate instance-lifecycle binding metadata after Rust planning
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 131

```yaml
slice: 131
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount provider-lifecycle receipt metadata
owner_boundary:
  route_or_surface: migrated local-provider health/start/stop lifecycle
    receipts and the driver-to-provider-operations lifecycle binding handoff
  authority_gate: unchanged; migrated local-provider health/start/stop paths
    still require Rust `plan_model_mount_provider_lifecycle` output before JS
    receipt persistence
  execution_backend: unchanged; JS still supervises local provider process/state
    records while Rust model_mount owns provider lifecycle planning and hashes
  truth_path: canonical snake_case provider-lifecycle receipt metadata only;
    duplicate camelCase `modelMountProviderLifecycle*` and
    `providerLifecycleHash` receipt-detail keys no longer mirror Rust-planned
    provider lifecycle records
  projection_path: unchanged; provider health/control lifecycle receipts
    continue to project from the persisted receipt store with canonical binding
    fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
    - packages/runtime-daemon/src/model-mounting/provider-operations.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
    - packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires the canonical
    `model_mount_provider_lifecycle` handoff object from local provider drivers
  - receipt conformance fails if provider health/control receipt guards
    reintroduce retired camelCase provider-lifecycle binding keys
  - focused daemon tests assert provider health/start/stop receipt records use
    canonical provider-lifecycle binding metadata and reject retired aliases
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs packages/runtime-daemon/src/model-mounting/provider-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust-planned
    provider lifecycle hashes/evidence against persisted health/control receipt
    fields while conformance rejects retired camelCase binding keys
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - at the time of this slice, model-instance state still carried
      `providerLifecycleHash`; Slice 133 later canonicalizes that state field
      to `model_mount_provider_lifecycle_hash`
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 132

```yaml
slice: 132
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-mount provider-inventory receipt metadata
owner_boundary:
  route_or_surface: local-provider `listModels` and `listLoaded` inventory
    envelopes plus provider-inventory lifecycle receipts
  authority_gate: unchanged; migrated local-provider inventory receipts still
    require provider kind plus Rust `plan_model_mount_provider_inventory`
    action/status/hash/evidence before JS receipt persistence
  execution_backend: unchanged; JS still reads local provider model and loaded
    instance records while Rust model_mount owns inventory envelope planning and
    hashes
  truth_path: canonical snake_case provider-inventory receipt metadata only;
    duplicate camelCase `modelMountProviderInventory*` and local
    `inventoryHash`/`inventoryEvidenceRefs`/`inventoryItemCount` aliases no
    longer mirror Rust-planned inventory records
  projection_path: unchanged; provider inventory lifecycle receipts continue to
    project from the persisted receipt store with canonical binding fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs
    - packages/runtime-daemon/src/model-mounting/provider-operations.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs
    - packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires the canonical
    `model_mount_provider_inventory` handoff object and `inventory_hash`
    metadata from local provider drivers
  - receipt conformance fails if provider-inventory receipt guards reintroduce
    retired camelCase provider-inventory binding keys
  - focused daemon tests assert provider model/list-loaded receipt records use
    canonical provider-inventory binding metadata and reject retired aliases
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs packages/runtime-daemon/src/model-mounting/provider-operations.mjs packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust-planned
    provider inventory hashes/evidence against persisted model/list-loaded
    receipt fields while conformance rejects retired camelCase binding keys
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - JS still reads local provider model artifact and model-instance records
      before Rust plans returned inventory envelopes; this slice removes only
      duplicate provider-inventory receipt and driver handoff metadata
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 133

```yaml
slice: 133
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model-instance provider lifecycle state binding
owner_boundary:
  route_or_surface: migrated local-provider model-instance state and model
    lifecycle receipts for load, unload, idle-evict, and supersede transitions
  authority_gate: unchanged; migrated local-provider instance transitions still
    require Rust `plan_model_mount_instance_lifecycle` output bound to the
    provider lifecycle hash before JS state or receipt persistence
  execution_backend: unchanged; JS still supervises local provider process/state
    records while Rust model_mount owns lifecycle planning and hash validation
  truth_path: canonical `model_mount_provider_lifecycle_hash` persisted binding
    only; the Rust bridge emits `provider_lifecycle_hash` without the retired
    camelCase `providerLifecycleHash` compatibility alias
  projection_path: unchanged; model-instance state and lifecycle receipts
    project from the persisted store with canonical provider and instance
    lifecycle binding fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs
    - packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs
    - packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs
    - packages/runtime-daemon/src/model-mounting/loaded-instances.mjs
  rust_bridge:
    - crates/node/src/bin/ioi_step_module_bridge/mod.rs
  tests:
    - packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs
    - packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs
    - packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs
    - packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs
    - packages/runtime-daemon/src/model-mounting/store.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires Rust instance lifecycle results to expose
    `provider_lifecycle_hash` and prove the retired `providerLifecycleHash`
    bridge alias is absent
  - receipt conformance requires migrated model-instance state and lifecycle
    receipts to carry `model_mount_provider_lifecycle_hash`
  - focused daemon tests assert load/unload/evict/supersede state and receipts
    use canonical provider lifecycle binding and reject retired aliases
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.mjs packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - cargo test -p ioi-node ioi_step_module_bridge::tests::bridge_plans_model_mount_instance_lifecycle_through_rust_core
    - node --test packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/store.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:receipts
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused model-mount tests compare Rust-planned
    instance lifecycle provider hashes against persisted state and receipt
    fields while conformance rejects retired camelCase provider lifecycle state
    aliases
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - JS still writes model-instance maps and lifecycle receipts after Rust
      plans migrated local provider instance transitions; this slice removes
      only the duplicate provider lifecycle hash alias on those state records
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 134

```yaml
slice: 134
phase: 10-authoritative-js-facade-retirement
objective: retire hosted fallback camelCase route policy alias
owner_boundary:
  route_or_surface: model-mount route selection and JS route-decision policy
    constraint metadata
  authority_gate: unchanged; route selection still requires Rust model_mount
    route-decision admission before provider invocation
  execution_backend: unchanged; JS still selects the candidate route while Rust
    admits the resolved route-decision record
  truth_path: canonical `allow_hosted_fallback` policy input and
    `allow_hosted_fallback` route-decision constraint only; retired
    `allowHostedFallback` no longer enables hosted fallback selection
  projection_path: unchanged; route-selection receipts and route-decision
    projections continue to derive from admitted receipt details
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/routes.mjs
    - packages/runtime-daemon/src/model-mounting/route-decision.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/routes.test.mjs
    - packages/runtime-daemon/src/model-mounting/route-decision.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects production reintroduction of
    `allowHostedFallback` in route selection and route-decision policy
    constraints
  - focused route tests prove canonical `allow_hosted_fallback` enables hosted
    fallback while retired `allowHostedFallback` is ignored
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/routes.mjs packages/runtime-daemon/src/model-mounting/route-decision.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/route-decision.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/route-decision.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; this slice removes a policy input
    compatibility alias before Rust route-decision admission
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader route and workflow request helpers still accept other camelCase
      UI/client convenience fields; this slice removes only the hosted fallback
      policy alias from route selection
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 135

```yaml
slice: 135
phase: 10-authoritative-js-facade-retirement
objective: canonicalize model route-decision receipt and projection metadata
owner_boundary:
  route_or_surface: model-mount route-selection receipts, route-decision
    projections, receipt replay, workflow native invocation responses, and
    OpenAI-compatible native invocation responses
  authority_gate: unchanged; route selection still requires Rust model_mount
    route-decision admission before provider invocation
  execution_backend: unchanged; JS still selects the candidate route while Rust
    admits the resolved route-decision record
  truth_path: canonical `model_route_decision*` receipt-detail fields only;
    retired `modelRouteDecision*` detail keys no longer mirror route-decision
    payloads or feed replay/native response adapters
  projection_path: route-decision projection and receipt replay now read and
    expose canonical snake_case `model_route_decision` data without a legacy
    detail fallback
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/routes.mjs
    - packages/runtime-daemon/src/model-mounting/route-decision.mjs
    - packages/runtime-daemon/src/model-mounting/projections.mjs
    - packages/runtime-daemon/src/model-mounting/workflow-node.mjs
    - packages/runtime-daemon/src/openai-compat-routes.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/routes.test.mjs
    - packages/runtime-daemon/src/model-mounting/route-decision.test.mjs
    - packages/runtime-daemon/src/model-mounting/projections.test.mjs
    - packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs
    - packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs
    - packages/runtime-daemon/src/openai-compat-routes.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance requires canonical `model_route_decision_schema_version`,
    `model_route_decision_event_kind`, `model_route_decision_id`, and
    `model_route_decision` fields on route-selection receipt details
  - bridge conformance rejects production reintroduction of retired
    `modelRouteDecision*` detail reads/writes in route receipt, projection,
    workflow native response, and OpenAI-compatible native response surfaces
  - focused tests prove legacy-only `modelRouteDecision` receipt details no
    longer project or populate native response shapes
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/routes.mjs packages/runtime-daemon/src/model-mounting/route-decision.mjs packages/runtime-daemon/src/model-mounting/projections.mjs packages/runtime-daemon/src/model-mounting/workflow-node.mjs packages/runtime-daemon/src/openai-compat-routes.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/route-decision.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs packages/runtime-daemon/src/openai-compat-routes.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/route-decision.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs packages/runtime-daemon/src/openai-compat-routes.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused projection/native response tests compare
    canonical route-decision receipt details against projected replay and
    response data while negative canaries prove retired legacy-only details are
    ignored
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader route and workflow request helpers still accept other camelCase
      UI/client convenience fields; this slice removes only the admitted
      route-decision receipt/projection detail compatibility alias
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 136

```yaml
slice: 136
phase: 10-authoritative-js-facade-retirement
objective: retire hosted fallback thread-control policy alias
owner_boundary:
  route_or_surface: runtime thread/model control helpers that persist model
    route controls and derive model policy for daemon-owned route selection
  authority_gate: unchanged; runtime thread control still resolves model routes
    through daemon-owned model mounting and Rust model_mount route-decision
    admission
  execution_backend: unchanged; JS thread-control surface remains a
    non-authoritative product/control adapter
  truth_path: canonical `allow_hosted_fallback` model-control and policy field
    only; retired `allowHostedFallback` no longer persists in thread controls
    or converts into route-selection policy
  projection_path: runtime thread-control records expose canonical
    `allow_hosted_fallback` and keep route receipt binding on canonical
    `model_route_decision` receipt details
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/threads/thread-runtime-controls.mjs
    - packages/runtime-daemon/src/runtime-thread-control-surface.mjs
  tests:
    - packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs
    - packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects production reintroduction of
    `allowHostedFallback` in runtime thread-control policy helpers and the
    runtime thread-control surface
  - focused tests prove canonical `allow_hosted_fallback` persists and maps to
    model policy while retired `allowHostedFallback` is ignored
verification:
  commands:
    - node --check packages/runtime-daemon/src/threads/thread-runtime-controls.mjs packages/runtime-daemon/src/runtime-thread-control-surface.mjs packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused thread-control tests compare canonical
    model-control policy values against route-control persistence while
    negative canaries prove retired hosted-fallback aliases are ignored
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - SDK/IDE structured policy helper types still expose camelCase UI
      convenience names; this slice removes the daemon translator that could
      convert the retired hosted-fallback alias into admitted route policy
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 137

```yaml
slice: 137
phase: 10-authoritative-js-facade-retirement
objective: retire hosted fallback SDK/IDE policy helper alias
owner_boundary:
  route_or_surface: agent SDK model-selection/thread-control helper types and
    Hypervisor IDE structured model-policy composer
  authority_gate: unchanged; SDK/IDE helpers remain clients of daemon-owned
    model route selection and Rust model_mount route-decision admission
  execution_backend: unchanged; no new runtime or client-side authority path
  truth_path: canonical `allow_hosted_fallback` helper field only; retired
    `allowHostedFallback` is no longer exported by SDK types or normalized by
    the IDE structured policy composer
  projection_path: SDK runtime thread-control models and IDE compiled policy
    model rules expose canonical `allow_hosted_fallback`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  sdk:
    - packages/agent-sdk/src/messages.ts
    - packages/agent-sdk/src/options.ts
    - packages/agent-sdk/src/substrate-client.ts
  ide:
    - packages/agent-ide/src/runtime/workflow-structured-policy-composer.ts
  tests:
    - packages/agent-ide/src/runtime/workflow-structured-policy-composer.test.ts
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects `allowHostedFallback` in SDK model helper types
    and the IDE structured policy composer
  - focused IDE test proves canonical `allow_hosted_fallback` is preserved while
    retired `allowHostedFallback` policy input is ignored
verification:
  commands:
    - npx tsc -p packages/agent-sdk/tsconfig.json --noEmit
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: not_applicable; this slice removes SDK/IDE
    policy-helper alias exports and locks the IDE policy composer with a
    focused canonical-field canary
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - other SDK/IDE convenience field aliases still exist outside the hosted
      fallback policy path and should be retired by surface-specific slices
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 138

```yaml
slice: 138
phase: 10-authoritative-js-facade-retirement
objective: retire IDE legacy model-id capability projection
owner_boundary:
  route_or_surface: Hypervisor IDE model capability binding normalizer
  authority_gate: unchanged; IDE model bindings remain clients of daemon-owned
    model route selection, wallet authority, and Rust model_mount admission
  execution_backend: unchanged; no IDE-side model execution path is introduced
  truth_path: raw model IDs are descriptive metadata only; executable model
    capability refs come from explicit `modelCapabilityRef` or canonical route
    projection, and readiness requires canonical credential metadata
  projection_path: IDE model binding projections use `model-capability:<route>`
    defaults and no longer mint `model-capability:legacy.*` refs from raw
    `modelId`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-model-capability-binding.ts
  tests:
    - packages/agent-ide/src/runtime/workflow-model-capability-binding.test.ts
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects reintroduction of the
    `legacyModelIdToModelCapabilityRef` helper, `model-capability:legacy`
    projection, or model-id-as-readiness language in the IDE model capability
    binding normalizer
  - focused IDE tests prove raw model IDs no longer mint executable legacy
    capability refs while canonical readiness metadata still makes a binding
    executable
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --import tsx --test packages/agent-ide/src/runtime/workflow-model-capability-binding.test.ts
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused normalizer tests compare raw model-id
    input against canonical route-derived capability refs and canonical
    credential metadata against executable readiness
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - broader workflow model binding shapes still carry descriptive `modelId`
      metadata and UI fallback policy fields; this slice retires only the
      executable capability/ref and readiness compatibility projection
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 139

```yaml
slice: 139
phase: 10-authoritative-js-facade-retirement
objective: retire route-decision camelCase fallback request aliases
owner_boundary:
  route_or_surface: daemon model-mount route-decision request metadata
  authority_gate: unchanged; fallback route decisions remain daemon-owned and
    Rust model_mount-admitted before provider invocation
  execution_backend: unchanged; no new execution path
  truth_path: canonical `fallback_triggered` and `fallback_reason` request
    metadata only; retired `fallbackTriggered` and `fallbackReason` no longer
    influence accepted route-decision receipts
  projection_path: route-decision object projection is unchanged; this slice
    retires request/admission alias reads only
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/model-mounting/route-decision.mjs
  tests:
    - packages/runtime-daemon/src/model-mounting/route-decision.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects `request.fallbackTriggered` and
    `request.fallbackReason` reads in the route-decision module while requiring
    canonical `request.fallback_triggered` and `request.fallback_reason`
  - focused daemon tests prove canonical fallback metadata is honored, retired
    camelCase fallback request aliases are ignored, and stale fields are still
    stripped from provider-bound request bodies
verification:
  commands:
    - node --check packages/runtime-daemon/src/model-mounting/route-decision.mjs packages/runtime-daemon/src/model-mounting/route-decision.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/model-mounting/route-decision.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused route-decision tests compare canonical
    fallback request metadata against accepted decision evidence/rationale while
    retired camelCase alias input remains inert
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - route-decision output object fields still use existing camelCase shape
      for SDK/IDE projection consumers; this slice removes only stale
      request/admission alias reads
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 140

```yaml
slice: 140
phase: 10-authoritative-js-facade-retirement
objective: retire runtime usage payload `eventKind` aliases
owner_boundary:
  route_or_surface: daemon runtime event payload summaries for usage and
    context-pressure telemetry
  authority_gate: unchanged; event summaries remain projections over admitted
    runtime events
  execution_backend: unchanged
  truth_path: canonical `event_kind` payload summary field only; duplicate
    `eventKind` aliases no longer emit from usage/context-pressure summaries
  projection_path: runtime payload summaries for `usage_delta`,
    `context_pressure_delta`, `context_pressure_alert`, and `usage_final`
    expose canonical snake_case event kind fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-event-payloads.mjs
  tests:
    - packages/runtime-daemon/src/runtime-event-payloads.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `eventKind` emission from runtime usage and
    context-pressure payload summaries
  - focused daemon tests assert all four migrated payload summary kinds expose
    `event_kind` without duplicate `eventKind`
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-event-payloads.mjs packages/runtime-daemon/src/runtime-event-payloads.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-event-payloads.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused payload tests compare usage and
    context-pressure projections against canonical `event_kind` output while
    asserting the retired alias key is absent
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - IDE typed projection records still use `eventKind` as a post-projection UI
      identity in some surfaces; this slice removes duplicate raw daemon payload
      summary emission only
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 141

```yaml
slice: 141
phase: 10-authoritative-js-facade-retirement
objective: retire runtime usage/context-pressure producer payload aliases
owner_boundary:
  route_or_surface: daemon runtime usage event producer payloads for usage
    deltas, context-pressure deltas, and context-pressure alerts
  authority_gate: unchanged; event records remain daemon projections over
    admitted runtime transitions
  execution_backend: unchanged
  truth_path: canonical snake_case payload fields only; duplicate camelCase
    producer aliases no longer emit from daemon usage/context-pressure payloads
  projection_path: runtime event records still carry canonical envelope fields;
    IDE typed projections may adapt after the protocol boundary
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-usage-events.mjs
  tests:
    - packages/runtime-daemon/src/runtime-usage-events.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects daemon usage/context-pressure producer
    payload alias emission
  - focused daemon tests assert usage delta, context-pressure delta,
    context-pressure alert, and nested alert actions omit retired camelCase keys
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-usage-events.mjs packages/runtime-daemon/src/runtime-usage-events.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-usage-events.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused producer tests compare generated
    usage/context-pressure payloads against canonical snake_case output while
    asserting retired alias keys are absent
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - `runtime-event-payloads.mjs` and `usage-telemetry.mjs` still contain
      reader-side/input alias handling for older records and provider telemetry;
      follow-up slices should retire those once canonical producers and
      persisted fixtures are verified
    - IDE typed projection records may keep post-projection camelCase UI shapes;
      raw daemon payload producers are canonical-only after this slice
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 142

```yaml
slice: 142
phase: 10-authoritative-js-facade-retirement
objective: retire runtime event usage/context-pressure summary reader aliases
owner_boundary:
  route_or_surface: daemon runtime event payload summary projection for usage
    deltas, context-pressure deltas, context-pressure alerts, and usage-final
    records
  authority_gate: unchanged; summary projection remains non-authoritative over
    daemon runtime events
  execution_backend: unchanged
  truth_path: canonical snake_case payload data only; retired camelCase
    usage/context-pressure data aliases no longer influence summary projection
  projection_path: runtime payload summaries expose canonical event kinds and
    canonical snake_case usage/context-pressure fields
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-event-payloads.mjs
  tests:
    - packages/runtime-daemon/src/runtime-event-payloads.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects retired camelCase usage/context-pressure
    payload data reads in runtime payload summary blocks
  - focused daemon tests prove legacy-only usage/context-pressure summary input
    aliases are ignored and default/fail-closed values are used
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-event-payloads.mjs packages/runtime-daemon/src/runtime-event-payloads.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-event-payloads.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused payload-summary tests compare canonical
    usage/context-pressure summary projection against legacy-only alias data
    that now falls back instead of shaping the summary
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - `usage-telemetry.mjs` still emits and aggregates camelCase telemetry
      aliases for run/thread/subagent records; follow-up slices should retire
      those producers after canonical telemetry consumers are verified
    - non-usage runtime payload summary families still contain their own
      historical camelCase input handling and need separate route-family review
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 143

```yaml
slice: 143
phase: 10-authoritative-js-facade-retirement
objective: retire runtime usage telemetry output aliases
owner_boundary:
  route_or_surface: daemon runtime usage telemetry records, summaries, and
    list envelopes
  authority_gate: unchanged; telemetry remains daemon projection input over
    admitted runtime state
  execution_backend: unchanged
  truth_path: canonical snake_case telemetry output only; duplicate camelCase
    telemetry fields no longer emit from run/thread/list/summary producers
  projection_path: runtime usage telemetry can still be adapted by typed IDE
    projections after the protocol boundary
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/usage-telemetry.mjs
  tests:
    - packages/runtime-daemon/src/usage-telemetry.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance requires runtime usage telemetry producer output
    aliases to remain retired
  - focused daemon tests assert run telemetry, thread aggregate telemetry,
    summary telemetry, and list envelopes emit canonical fields only
verification:
  commands:
    - node --check packages/runtime-daemon/src/usage-telemetry.mjs packages/runtime-daemon/src/usage-telemetry.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/usage-telemetry.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused telemetry tests compare generated
    run/thread/list/summary telemetry against canonical snake_case output while
    asserting retired alias keys are absent
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - `usage-telemetry.mjs` still accepts camelCase input from older run,
      provider, route, and subagent records; those reader aliases should be
      retired once canonical persisted records and provider inputs are verified
    - `runtime-usage-events.mjs` still accepts camelCase usage telemetry input
      as a downstream reader-side compatibility layer
    - SDK and IDE typed telemetry projections may still expose camelCase UI
      shapes after the protocol boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 144

```yaml
slice: 144
phase: 10-authoritative-js-facade-retirement
objective: retire runtime usage event telemetry input aliases
owner_boundary:
  route_or_surface: daemon runtime usage event delta producer
  authority_gate: unchanged; usage deltas remain daemon projections over
    canonical runtime usage telemetry
  execution_backend: unchanged
  truth_path: canonical snake_case usage telemetry input only; retired
    camelCase telemetry fields no longer influence usage delta generation
  projection_path: runtime usage/context-pressure delta payloads remain
    canonical snake_case
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-usage-events.mjs
  tests:
    - packages/runtime-daemon/src/runtime-usage-events.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects stale `usageTelemetry.*` camelCase reads in
    the runtime usage delta producer
  - focused daemon tests prove legacy-only telemetry alias input falls back to
    canonical defaults instead of shaping usage/context-pressure deltas
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-usage-events.mjs packages/runtime-daemon/src/runtime-usage-events.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-usage-events.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused usage-event tests compare canonical
    usage telemetry input against legacy-only alias input that no longer shapes
    accepted runtime usage/context-pressure payloads
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - `usage-telemetry.mjs` still accepts camelCase input from older run,
      provider, route, and subagent records; this slice retires only the
      downstream runtime usage-event reader
    - SDK and IDE typed telemetry projections may still expose camelCase UI
      shapes after the protocol boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 145

```yaml
slice: 145
phase: 10-authoritative-js-facade-retirement
objective: retire runtime usage telemetry reader aliases
owner_boundary:
  route_or_surface: daemon runtime usage telemetry run/thread/subagent
    aggregation and summary readers
  authority_gate: unchanged; telemetry remains a projection input over admitted
    runtime state
  execution_backend: unchanged
  truth_path: canonical snake_case run/provider/route/subagent usage telemetry
    input only; retired camelCase input data aliases no longer influence
    generated telemetry records
  projection_path: runtime usage telemetry records, summaries, list envelopes,
    and usage/context-pressure deltas remain canonical snake_case
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/usage-telemetry.mjs
  tests:
    - packages/runtime-daemon/src/usage-telemetry.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects retired camelCase run/provider/route/subagent
    telemetry data reads in `usage-telemetry.mjs`
  - focused daemon tests prove legacy-only run/provider/route/subagent telemetry
    aliases fall back to canonical defaults instead of shaping telemetry output
verification:
  commands:
    - node --check packages/runtime-daemon/src/usage-telemetry.mjs packages/runtime-daemon/src/usage-telemetry.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/usage-telemetry.test.mjs
    - node --test packages/runtime-daemon/src/runtime-usage-events.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused telemetry tests compare canonical
    usage records against legacy-only alias data that no longer shapes run,
    thread, subagent, aggregate, or summary telemetry
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - higher-level route/API/SDK/IDE surfaces may still accept camelCase request
      or typed UI shapes before canonicalizing into daemon telemetry records
    - non-usage runtime payload summary families still contain historical
      camelCase input handling and need separate route-family review
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 146

```yaml
slice: 146
phase: 10-authoritative-js-facade-retirement
objective: retire thread and turn usage projection aliases
owner_boundary:
  route_or_surface: daemon thread/turn projection usage telemetry fields
  authority_gate: unchanged; thread/turn records remain read projections over
    admitted runtime state
  execution_backend: unchanged
  truth_path: thread/turn projections publish canonical `usage_telemetry` plus
    the existing `usage` projection field; retired `usageTelemetry`,
    `runtimeUsage`, and `runtime_usage` compatibility fields no longer emit
  projection_path: turn projection reads canonical run usage only and ignores
    legacy-only camelCase run usage telemetry aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/threads/thread-turn-projection.mjs
  tests:
    - packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects thread/turn projection emission of retired
    usage alias fields
  - compositor conformance rejects turn projection reads from legacy-only
    `run.usageTelemetry` and `run.runtimeUsage`
  - focused daemon tests prove legacy-only run usage aliases fall back to the
    canonical usage calculation instead of shaping turn projection output
verification:
  commands:
    - node --check packages/runtime-daemon/src/threads/thread-turn-projection.mjs packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused thread-turn projection tests compare
    canonical usage projection output against legacy-only run usage aliases
    that no longer shape turn usage
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - run records and trace bundles still expose some camelCase usage telemetry
      aliases outside the thread/turn projection surface
    - SDK and IDE typed telemetry projections may still expose camelCase UI
      shapes after the protocol boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 147

```yaml
slice: 147
phase: 10-authoritative-js-facade-retirement
objective: retire runtime agent run lifecycle usage output aliases
owner_boundary:
  route_or_surface: extracted daemon runtime agent run lifecycle records
  authority_gate: unchanged; run lifecycle creation remains daemon-owned record
    assembly over admitted runtime context
  execution_backend: unchanged
  truth_path: run and trace lifecycle records publish canonical `usage_telemetry`
    plus the existing `usage` projection field; retired `usageTelemetry` and
    `runtimeUsage` compatibility fields no longer emit from this extracted
    lifecycle path
  projection_path: lifecycle tests verify run and trace records expose one
    canonical usage telemetry projection object through `usage_telemetry`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs
  tests:
    - packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects lifecycle emission of retired run/trace usage
    alias fields
  - focused daemon tests assert `usageTelemetry` and `runtimeUsage` are absent
    from created run and trace records
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused lifecycle tests compare canonical
    `usage`/`usage_telemetry` identity against absent retired camelCase aliases
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - the monolithic `index.mjs` run/trace assembly and runtime bridge record
      projection still expose camelCase usage telemetry aliases
    - context-budget, subagent, SDK, and IDE typed telemetry surfaces still need
      separate compatibility retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 148

```yaml
slice: 148
phase: 10-authoritative-js-facade-retirement
objective: retire runtime bridge run record usage output aliases
owner_boundary:
  route_or_surface: RuntimeAgentService bridge run/trace projection records
  authority_gate: unchanged; bridge records remain daemon read projections over
    canonical runtime events
  execution_backend: unchanged
  truth_path: bridge run and trace records publish canonical `usage_telemetry`
    plus the existing `usage` projection field; retired `usageTelemetry` and
    `runtimeUsage` compatibility fields no longer emit from bridge records or
    trace artifacts
  projection_path: bridge record tests verify run, trace, and trace artifact
    records expose canonical usage telemetry only
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-record-projections.mjs
  tests:
    - packages/runtime-daemon/src/runtime-record-projections.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects bridge run/trace emission of retired usage
    alias fields
  - focused daemon tests assert `usageTelemetry` and `runtimeUsage` are absent
    from bridge run records, trace records, and trace artifact content
verification:
  commands:
    - node --check packages/runtime-daemon/src/runtime-record-projections.mjs packages/runtime-daemon/src/runtime-record-projections.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-record-projections.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused bridge projection tests compare canonical
    `usage`/`usage_telemetry` identity against absent retired camelCase aliases
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - the monolithic `index.mjs` run/trace assembly still exposes camelCase
      usage telemetry aliases
    - context-budget, subagent, SDK, and IDE typed telemetry surfaces still need
      separate compatibility retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 149

```yaml
slice: 149
phase: 10-authoritative-js-facade-retirement
objective: retire runtime bridge turn usage result aliases
owner_boundary:
  route_or_surface: RuntimeAgentService bridge turn-submit normalization
  authority_gate: unchanged; bridge turn submit remains a daemon projection over
    RuntimeAgentService results
  execution_backend: unchanged
  truth_path: bridge turn submit usage projection accepts canonical
    `usage_telemetry` plus the existing `usage` field only; retired
    `usageTelemetry`, `runtime_usage`, and `runtimeUsage` result aliases no
    longer shape the normalized run projection
  projection_path: bridge-turn tests verify canonical usage flows and
    legacy-only usage aliases fall back to null
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs
  tests:
    - packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects bridge turn normalization reads from retired
    usage result aliases
  - focused daemon tests prove canonical `usage_telemetry` wins and legacy-only
    aliases no longer influence bridge turn usage projection
verification:
  commands:
    - node --check packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused bridge-turn tests compare canonical
    `usage_telemetry` input against legacy-only result aliases that no longer
    shape normalized projections
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - the monolithic `index.mjs` run/trace assembly still exposes camelCase
      usage telemetry aliases
    - context-budget, subagent, SDK, and IDE typed telemetry surfaces still need
      separate compatibility retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 150

```yaml
slice: 150
phase: 10-authoritative-js-facade-retirement
objective: retire monolithic daemon run/trace usage aliases
owner_boundary:
  route_or_surface: monolithic daemon run and trace assembly in `index.mjs`
  authority_gate: unchanged; daemon run assembly remains a projection over the
    admitted runtime context
  execution_backend: unchanged
  truth_path: daemon run/trace records publish canonical `usage_telemetry` plus
    the existing `usage` projection field only; retired `usageTelemetry`,
    `runtime_usage`, and `runtimeUsage` request/output aliases no longer shape
    or emit from the monolithic path
  projection_path: compositor conformance verifies canonical
    `model_route_decision` usage-telemetry input and absence of retired usage
    aliases in `index.mjs`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/index.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects monolithic daemon reads from retired usage
    request aliases
  - compositor conformance rejects monolithic daemon run/trace emission of
    retired usage output aliases
verification:
  commands:
    - node --check packages/runtime-daemon/src/index.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-run-cancellation.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: compositor conformance compares the monolithic
    run/trace assembly source against the extracted lifecycle and bridge
    projection alias-retirement contract
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - context-budget, subagent, SDK, and IDE typed telemetry surfaces still need
      separate compatibility retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 151

```yaml
slice: 151
phase: 10-authoritative-js-facade-retirement
objective: retire context-budget usage telemetry input aliases
owner_boundary:
  route_or_surface: daemon context-budget policy usage telemetry inputs and
    summary aggregation
  authority_gate: unchanged; context-budget evaluation remains a daemon policy
    gate over canonical runtime usage telemetry
  execution_backend: unchanged
  truth_path: context-budget policy reads canonical `usage_telemetry`,
    `budget_usage_telemetry`, and existing `usage` projection inputs only;
    retired runtime usage meter and camelCase telemetry aliases no longer shape
    policy decisions
  projection_path: context-budget policy result emission is unchanged for this
    slice; summary aggregation ignores retired camelCase telemetry row/id data
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/threads/context-budget-policy.mjs
  tests:
    - packages/runtime-daemon/src/threads/context-budget-policy.test.mjs
    - packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects context-budget reads from retired
    `usageTelemetry`, `runtimeUsageMeter`, `runtime_usage_meter`,
    `budgetUsageTelemetry`, `runtimeTelemetrySummary`, and
    `runtime_telemetry_summary` request/config aliases
  - focused daemon tests prove retired request and telemetry-row aliases fall
    back to null/defaults instead of shaping context-budget decisions
verification:
  commands:
    - node --check packages/runtime-daemon/src/threads/context-budget-policy.mjs packages/runtime-daemon/src/threads/context-budget-policy.test.mjs packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/threads/context-budget-policy.test.mjs packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused tests compare canonical usage telemetry
    inputs against retired request/data aliases that no longer shape policy
    summaries or block decisions
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - context-budget policy result payloads still emit some camelCase response
      aliases and threshold aliases for a follow-up facade-retirement slice
    - subagent, SDK, and IDE typed telemetry surfaces still need separate
      compatibility retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 152

```yaml
slice: 152
phase: 10-authoritative-js-facade-retirement
objective: retire subagent budget usage telemetry input aliases
owner_boundary:
  route_or_surface: daemon subagent budget/usage telemetry helpers
  authority_gate: unchanged; subagent budget evaluation remains a daemon policy
    gate over canonical runtime usage telemetry
  execution_backend: unchanged
  truth_path: subagent budget usage reads canonical `budget_usage_telemetry`
    and canonical snake_case telemetry fields only; retired camelCase request,
    telemetry-row, and model-route aliases no longer shape subagent budget
    policy decisions
  projection_path: subagent output/result/event payload compatibility aliases
    remain unchanged for this slice
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
  tests:
    - packages/runtime-daemon/src/subagent-manager.test.mjs
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects subagent budget usage reads from retired
    `budgetUsageTelemetry`, `runtimeTelemetrySummary`,
    `runtime_telemetry_summary`, camelCase usage data, and
    `run.modelRouteDecision` aliases
  - focused daemon tests prove retired request and previous-usage aliases fall
    back to null/defaults instead of shaping subagent budget decisions
verification:
  commands:
    - node --check packages/runtime-daemon/src/subagent-manager.mjs packages/runtime-daemon/src/subagent-manager.test.mjs scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused tests compare canonical subagent usage
    telemetry inputs against retired request/data aliases that no longer shape
    budget status or cumulative usage
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent budget/result/event payloads still emit camelCase response
      aliases and read general record identity/status aliases for a follow-up
      facade-retirement slice
    - SDK and IDE typed telemetry surfaces still need separate compatibility
      retirement
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 153

```yaml
slice: 153
phase: 10-authoritative-js-facade-retirement
objective: retire IDE context-budget usage request aliases
owner_boundary:
  route_or_surface: Hypervisor IDE runtime context-budget control node request
    builder and telemetry-source binding templates
  authority_gate: unchanged; IDE still composes daemon policy requests and does
    not admit runtime truth
  execution_backend: unchanged
  truth_path: IDE context-budget requests send canonical `usage_telemetry`
    only; retired `runtimeUsageMeter`, `runtimeTelemetrySummary`, and
    `usageTelemetry` request aliases no longer shape generated daemon requests
  projection_path: context-budget result inspection remains unchanged
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.test.ts
    - packages/agent-ide/src/runtime/workflow-node-registry.ts
    - packages/agent-ide/src/runtime/workflow-validation.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
    - scripts/lib/workflow-runtime-event-projection-contract.test.mjs
    - scripts/lib/workflow-telemetry-budget-chain-creator-gui-probe.mjs
    - scripts/lib/live-runtime-daemon-contract.test.mjs
conformance_checks:
  - compositor conformance rejects IDE context-budget request reads from retired
    usage alias fields and requires canonical `usage_telemetry`
  - focused IDE tests prove retired usage aliases no longer populate daemon
    context-budget request bodies
verification:
  commands:
    - node --test packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.test.ts packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.test.ts
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused IDE request-builder tests compare
    canonical `usage_telemetry` inputs against retired aliases that no longer
    shape daemon request bodies
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - coding-tool and subagent IDE budget control nodes still expose
      `budgetUsageTelemetry` and `runtimeTelemetrySummary` compatibility shapes
      for separate facade-retirement slices
    - context-budget policy result and telemetry-summary projection objects
      still contain camelCase view-model fields outside this request boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 154

```yaml
slice: 154
phase: 10-authoritative-js-facade-retirement
objective: retire IDE telemetry budget-chain hydration edge aliases
owner_boundary:
  route_or_surface: Hypervisor IDE runtime telemetry budget-chain
    materialization and existing-chain hydration
  authority_gate: unchanged; IDE still composes daemon policy requests and does
    not admit runtime truth
  execution_backend: unchanged
  truth_path: IDE materialization recognizes only canonical `usage_telemetry`
    usage-to-context-budget edges when hydrating an existing context-budget
    chain
  projection_path: context-budget result inspection remains unchanged
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects old `runtimeUsageMeter` usage-to-context
    edge-port checks in telemetry budget-chain materialization
  - focused IDE materialization coverage proves canonical `usage_telemetry`
    edges hydrate instead of causing duplicate chain insertion
verification:
  commands:
    - node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused IDE materialization coverage compares
    canonical template edge ports against the existing-chain hydration detector
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - coding-tool and subagent IDE budget control nodes still expose
      `budgetUsageTelemetry` and `runtimeTelemetrySummary` compatibility shapes
      for separate facade-retirement slices
    - context-budget policy result and telemetry-summary projection objects
      still contain camelCase view-model fields outside this request boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 155

```yaml
slice: 155
phase: 10-authoritative-js-facade-retirement
objective: retire IDE coding-tool budget usage request output alias
owner_boundary:
  route_or_surface: Hypervisor IDE runtime coding-tool control request builder
  authority_gate: unchanged; IDE still composes daemon tool requests and does
    not admit runtime truth
  execution_backend: unchanged
  truth_path: generated coding-tool daemon requests emit canonical
    `budget_usage_telemetry` only; duplicate `budgetUsageTelemetry` is no
    longer present on the request body
  projection_path: coding-tool budget evidence projection remains unchanged
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts
    - packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.test.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
    - scripts/lib/workflow-runtime-event-projection-contract.test.mjs
    - scripts/lib/workflow-telemetry-budget-chain-creator-gui-probe.mjs
    - scripts/lib/live-runtime-daemon-contract.test.mjs
conformance_checks:
  - compositor conformance rejects `budgetUsageTelemetry` as a coding-tool
    control request body field and requires canonical `budget_usage_telemetry`
  - focused IDE request-builder tests prove the duplicate body field is absent
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: contract and IDE source tests compare generated
    coding-tool budget requests against the canonical daemon request field
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - coding-tool graph input fields still use `runtimeTelemetrySummary` and
      `budgetUsageField` as internal workflow binding names until the graph
      binding migration retires them
    - subagent IDE budget control nodes still expose `budgetUsageTelemetry` and
      `runtimeTelemetrySummary` compatibility shapes for a separate
      facade-retirement slice
    - daemon coding-tool governance/invocation responses still expose
      `budgetUsageTelemetry` response aliases outside this IDE request boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 156

```yaml
slice: 156
phase: 10-authoritative-js-facade-retirement
objective: retire IDE subagent budget usage request output alias
owner_boundary:
  route_or_surface: Hypervisor IDE runtime subagent control request builder
  authority_gate: unchanged; IDE still composes daemon subagent requests and
    does not admit runtime truth
  execution_backend: unchanged
  truth_path: generated subagent daemon requests emit canonical
    `budget_usage_telemetry` only; duplicate `budgetUsageTelemetry` is no
    longer present on the request body
  projection_path: subagent budget evidence projection remains unchanged
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts
    - packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.test.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
    - scripts/lib/live-runtime-daemon-contract.test.mjs
conformance_checks:
  - compositor conformance rejects `budgetUsageTelemetry` as a subagent control
    request body field and requires canonical `budget_usage_telemetry`
  - focused IDE request-builder tests prove the duplicate body field is absent
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --check scripts/lib/live-runtime-daemon-contract.test.mjs
    - npm run build --workspace=@ioi/agent-ide
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: IDE source tests and live contract guards compare
    generated subagent budget requests against the canonical daemon request field
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent graph input fields still use `runtimeTelemetrySummary` and
      `subagentBudgetUsageField` as internal workflow binding names until the
      graph binding migration retires them
    - daemon subagent response and record surfaces still expose camelCase
      receipt/policy/budget aliases outside this IDE request boundary
    - SDK subagent/result types still expose `usageTelemetry` aliases until the
      stable protocol type cleanup slice
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 157

```yaml
slice: 157
phase: 10-authoritative-js-facade-retirement
objective: retire daemon coding-tool budget usage response alias
owner_boundary:
  route_or_surface: runtime-daemon coding-tool invocation and governance
    budget-block response surfaces
  authority_gate: unchanged; budget blocks still fail closed before tool
    execution and emit policy receipts/events
  execution_backend: unchanged
  truth_path: daemon coding-tool budget block errors and event payload summaries
    expose canonical `budget_usage_telemetry` only; duplicate
    `budgetUsageTelemetry` is no longer emitted
  projection_path: coding-tool budget block events remain canonical
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs
    - packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs
    - packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs
    - packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - bridge conformance rejects duplicate `budgetUsageTelemetry` on coding-tool
    budget block response surfaces and requires canonical
    `budget_usage_telemetry`
  - focused daemon tests prove invocation errors and governance event payloads
    omit the duplicate response alias
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs
    - npm run hypervisor-conformance:bridge
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare budget-block
    invocation/governance response payloads against the canonical field
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - coding-tool budget policy internals still expose camelCase policy object
      fields outside this response boundary
    - context-budget/result and runtime telemetry summary view-model aliases
      remain for separate projection-shape retirement slices
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 158

```yaml
slice: 158
phase: 10-authoritative-js-facade-retirement
objective: retire daemon subagent budget usage output alias
owner_boundary:
  route_or_surface: runtime-daemon subagent spawn/input/resume record surfaces
  authority_gate: unchanged; subagent budget blocks still fail closed before
    continuation and emit policy/event evidence
  execution_backend: unchanged
  truth_path: daemon subagent records expose canonical `budget_usage_telemetry`
    only; duplicate `budgetUsageTelemetry` is no longer emitted on updated
    records or blocked error payloads
  projection_path: subagent lifecycle events remain canonical
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate `budgetUsageTelemetry` on runtime
    subagent records and requires canonical `budget_usage_telemetry`
  - focused daemon tests prove spawn/input/resume records and blocked payloads
    omit the duplicate output alias
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare subagent
    spawn/input/resume records against the canonical budget usage field
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still emits broader camelCase record, event, and
      receipt/policy aliases outside this budget usage output boundary
    - subagent manager record projections still expose `usageTelemetry` aliases
      until the stable projection/type cleanup slices
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 159

```yaml
slice: 159
phase: 10-authoritative-js-facade-retirement
objective: retire daemon subagent usage telemetry output alias
owner_boundary:
  route_or_surface: runtime-daemon subagent spawn/input/resume record surfaces
  authority_gate: unchanged; subagent lifecycle and budget policy decisions
    still emit daemon-owned events before projection
  execution_backend: unchanged
  truth_path: daemon subagent records expose canonical `usage_telemetry` only;
    duplicate `usageTelemetry` is no longer emitted on updated records or
    blocked error payloads
  projection_path: subagent lifecycle events remain canonical
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate `usageTelemetry` on runtime
    subagent records and requires canonical `usage_telemetry`
  - focused daemon tests prove spawn/input/resume records and blocked payloads
    omit the duplicate output alias
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare subagent
    spawn/input/resume records against the canonical usage telemetry field
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still emits broader camelCase record, event, and
      receipt/policy aliases outside this usage telemetry output boundary
    - subagent manager record projections still read retired `usageTelemetry`
      aliases until the stable projection/type cleanup slices
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 160

```yaml
slice: 160
phase: 10-authoritative-js-facade-retirement
objective: retire subagent manager usage telemetry projection alias
owner_boundary:
  route_or_surface: runtime-daemon subagent manager result/event projection
    helpers
  authority_gate: unchanged; subagent lifecycle events remain daemon-owned
    projections over admitted records
  execution_backend: unchanged
  truth_path: subagent manager helper projections expose canonical
    `usage_telemetry` only and ignore retired `usageTelemetry` input fallback
  projection_path: subagent result and manager event payload helpers are
    canonical at the usage telemetry boundary
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate `usageTelemetry` in subagent
    manager projections and requires canonical `usage_telemetry`
  - focused daemon tests prove canonical subagent result/event payloads carry
    `usage_telemetry` only and legacy-only `usageTelemetry` does not revive the
    shim
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused helper tests compare subagent result and
    manager event projections against canonical usage telemetry fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent manager result/event projections still emit broader camelCase
      identity, budget, receipt, policy, cost, and token aliases outside this
      usage telemetry boundary
    - runtime subagent surface still emits broader camelCase record, event, and
      receipt/policy aliases outside the already-retired budget/usage
      telemetry output boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 161

```yaml
slice: 161
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent surface usage telemetry input alias
owner_boundary:
  route_or_surface: runtime-daemon subagent input/resume/cancel budget usage
    evaluation
  authority_gate: unchanged; subagent budget policy still decides before
    persisted lifecycle updates
  execution_backend: unchanged
  truth_path: subagent budget evaluation uses canonical `usage_telemetry` only
    when carrying previous usage into the next lifecycle operation
  projection_path: subagent records continue to emit canonical usage telemetry
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.usageTelemetry` reads in the
    runtime subagent surface
  - focused daemon tests prove a legacy-only `usageTelemetry` record fallback
    does not contribute to budget evaluation
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused daemon tests compare subagent budget
    evaluation against canonical previous usage semantics
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still reads broader camelCase request and record
      identity, receipt, policy, budget-status, and cancellation aliases outside
      this usage telemetry input boundary
    - subagent manager result/event projections still emit broader camelCase
      identity, budget, receipt, policy, cost, and token aliases
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 162

```yaml
slice: 162
phase: 10-authoritative-js-facade-retirement
objective: retire subagent budget usage telemetry output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent previous-usage telemetry
    normalizer
  authority_gate: unchanged; normalized previous usage still feeds daemon
    budget policy evaluation before lifecycle effects
  execution_backend: unchanged
  truth_path: previous-usage telemetry emits canonical snake_case fields only
  projection_path: subagent budget evidence no longer carries duplicate
    camelCase telemetry summary aliases from the normalizer
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes the normalizer block and rejects
    `schemaVersion`, cumulative-token, source, receipt, policy, and summary
    camelCase output aliases
  - focused daemon tests prove normalized previous usage exposes canonical
    snake_case fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused normalizer tests compare previous usage
    output against canonical snake_case telemetry fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent run-usage telemetry still emits broader camelCase token/cost
      aliases outside this previous-usage normalizer boundary
    - subagent manager result/event projections still emit broader camelCase
      identity, budget, receipt, policy, cost, and token aliases
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 163

```yaml
slice: 163
phase: 10-authoritative-js-facade-retirement
objective: retire subagent run usage telemetry output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent run-usage telemetry helper
  authority_gate: unchanged; run usage still feeds daemon budget policy before
    lifecycle writes
  execution_backend: unchanged
  truth_path: subagent run usage emits canonical snake_case telemetry fields
    only
  projection_path: subagent records continue to expose canonical
    `usage_telemetry`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes the `subagentUsageTelemetryForRun` block and
    rejects `schemaVersion`, token, cost, run-id, and model-route camelCase
    output aliases
  - focused daemon tests prove run usage telemetry exposes canonical snake_case
    fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused helper tests compare subagent run usage
    output against canonical telemetry fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent manager result/event projections still emit broader camelCase
      identity, budget, receipt, policy, cost, and token aliases
    - runtime subagent surface still reads broader camelCase request and record
      identity, receipt, policy, budget-status, and cancellation aliases
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 164

```yaml
slice: 164
phase: 10-authoritative-js-facade-retirement
objective: retire subagent result output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent result projection helper
  authority_gate: unchanged; result projection still derives from daemon-owned
    subagent records and run receipts
  execution_backend: unchanged
  truth_path: subagent result envelope emits canonical snake_case fields only
  projection_path: subagent result objects no longer duplicate identity,
    lifecycle, budget, contract, or receipt fields with camelCase aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes the `subagentResultForRun` block and rejects
    duplicate camelCase output fields
  - focused daemon tests prove result envelopes expose canonical snake_case
    fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused helper tests compare result envelopes
    against canonical identity, lifecycle, budget, usage, and receipt fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent manager event payloads still emit broader camelCase identity,
      lifecycle, budget, receipt, policy, cost, and token aliases
    - runtime subagent surface still emits broader camelCase record and
      error-detail aliases outside the result helper boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 165

```yaml
slice: 165
phase: 10-authoritative-js-facade-retirement
objective: retire subagent manager event payload output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent manager event payload projection
  authority_gate: unchanged; events still derive from daemon-owned subagent
    control records and admitted runtime event envelopes
  execution_backend: unchanged
  truth_path: runtime event payloads expose canonical snake_case fields only
  projection_path: IDE delegation matrix and SDK live proof consume canonical
    raw payload keys while their typed view models may retain camelCase UI/API
    properties
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  ide:
    - packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
    - scripts/lib/live-runtime-daemon-contract.test.mjs
conformance_checks:
  - compositor conformance scopes the `subagentManagerEventPayload` block and
    rejects duplicate camelCase event payload output fields
  - compositor conformance rejects IDE raw subagent manager payload reads from
    retired camelCase field aliases
  - live SDK contract proof asserts canonical raw payload
    `context_pressure_action`
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: focused helper tests compare event payloads
    against canonical identity, lifecycle, cost, token, and usage fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - subagent manager event payload still reads broader camelCase record
      inputs until the subagent record projection surface is canonicalized
    - runtime subagent surface still emits broader camelCase record and
      error-detail aliases outside the event payload boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 166

```yaml
slice: 166
phase: 10-authoritative-js-facade-retirement
objective: retire subagent manager event payload input aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent manager event payload projection
  authority_gate: unchanged; the event still comes from daemon-owned subagent
    control records before runtime event envelope admission
  execution_backend: unchanged
  truth_path: event payload materialization reads canonical top-level
    snake_case subagent record fields only
  projection_path: compositor conformance rejects camelCase-only record
    fallbacks at the event payload helper boundary
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/subagent-manager.mjs
    - packages/runtime-daemon/src/subagent-manager.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes `subagentManagerEventPayload` and rejects
    `record.*` reads from retired camelCase-only event input aliases
  - focused daemon tests prove retired record aliases and nested cancellation
    fallbacks do not materialize accepted event payload fields
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/subagent-manager.test.mjs packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests continue to prove
    daemon-created subagent records carry canonical event payload fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request fields
      while canonicalizing records before event payload creation
    - runtime subagent surface still emits broader camelCase record and
      error-detail aliases outside the event payload boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 167

```yaml
slice: 167
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent record projection output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent record projection surface
  authority_gate: unchanged; subagent records still come from daemon-owned
    lifecycle operations before runtime event envelope admission
  execution_backend: unchanged
  truth_path: subagent record projections expose canonical snake_case fields
    only; duplicate camelCase record aliases are filtered before returning to
    list/get/result/control callers
  projection_path: compositor conformance rejects camelCase field materializers
    inside `subagentProjection`
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes `subagentProjection` and rejects duplicate
    camelCase subagent record output fields
  - focused daemon tests prove list, spawn, blocked, wait, result, input,
    resume, assign, cancel, and propagated cancellation record outputs omit
    retired record aliases
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare returned
    subagent records against canonical projection fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while canonicalizing record projections
    - list/propagation envelopes and error details still expose broader
      camelCase response aliases outside the subagent record projection
      boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 168

```yaml
slice: 168
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent record write output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent lifecycle persistence surface
  authority_gate: unchanged; lifecycle writes still occur only through
    daemon-owned subagent control operations
  execution_backend: unchanged
  truth_path: persisted subagent records from spawn, wait, input, resume,
    assign, and cancel writes carry canonical snake_case top-level fields only
  projection_path: record projections already expose canonical fields; this
    slice removes the duplicate write shape behind those projections
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance counts canonicalized `saved` lifecycle writes and
    requires every `store.writeSubagent(saved, ...)` path to pass through the
    retired-alias filter
  - focused daemon tests prove persisted records from spawn, blocked spawn,
    wait, input, resume, blocked resume, assign, cancel, and propagated cancel
    omit retired top-level record aliases
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare stored
    lifecycle records against canonical projection fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical writes
    - list/propagation envelopes, nested input/resume/assignment/cancellation
      helper objects, and error details still expose broader camelCase response
      aliases outside the persisted subagent record boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 169

```yaml
slice: 169
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent list and propagation envelope aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent list and cancellation propagation
    response envelopes
  authority_gate: unchanged; list and propagation still project daemon-owned
    subagent records and cancellation events
  execution_backend: unchanged
  truth_path: list and propagation envelopes expose canonical snake_case
    response fields only
  projection_path: compositor conformance scopes the list/propagation response
    methods and rejects duplicate camelCase envelope aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `schemaVersion`, `threadId`,
    `parentAgentId`, count, refs, and collection camelCase aliases in the
    list/propagation envelope methods
  - focused daemon tests prove list envelopes, propagation envelopes, canceled
    subagent records, and skipped subagent records omit retired response aliases
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare list and
    propagation responses against canonical envelope fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical writes and envelopes
    - nested input/resume/assignment/cancellation helper objects and error
      details still expose broader camelCase response aliases outside this
      envelope boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 170

```yaml
slice: 170
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent nested helper output aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent input, resume, assignment, and
    cancellation helper response objects
  authority_gate: unchanged; helper records still come from daemon-owned
    subagent lifecycle operations
  execution_backend: unchanged
  truth_path: nested helper objects expose canonical snake_case fields only
    and no longer persist duplicate camelCase aliases into subagent histories
    or cancellation metadata
  projection_path: compositor conformance scopes helper construction blocks and
    rejects duplicate camelCase helper aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate camelCase fields in `inputRecord`,
    `resumeRecord`, `assignmentRecord`, and nested `cancellation` objects
  - focused daemon tests prove returned helper objects and persisted
    `input_history`, `resume_history`, `assignment_history`, and `cancellation`
    metadata omit retired helper aliases
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare returned
    and persisted helper objects against canonical snake_case fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical writes, envelopes, and
      helper outputs
    - error details still expose broader camelCase response aliases outside
      this helper-object boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 171

```yaml
slice: 171
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent error-detail aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent validation and policy error details
  authority_gate: unchanged; validation errors still fail closed before
    lifecycle side effects, and budget policy errors still persist blocked
    daemon-owned records before returning policy failure
  execution_backend: unchanged
  truth_path: subagent not-found, validation, concurrency, canceled-input, and
    budget-block errors expose canonical snake_case detail fields only
  projection_path: compositor conformance scopes error-detail construction
    blocks and rejects duplicate camelCase error aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate camelCase fields in subagent
    not-found, missing-prompt, concurrency, canceled-input, missing-input, and
    budget policy error details
  - focused daemon tests prove error details expose `thread_id`,
    `subagent_id`, `event_id`, `receipt_refs`, and `policy_decision_refs`
    where applicable without retired camelCase aliases
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare thrown
    error details against canonical snake_case fields
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical writes, envelopes, helper
      outputs, and error details
    - non-error lifecycle response envelopes such as wait, resume, assign, and
      cancel still expose compatibility aliases outside this error-detail
      boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 172

```yaml
slice: 172
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent lifecycle result envelope aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent wait, resume, and cancel success
    envelopes
  authority_gate: unchanged; lifecycle operations still run through
    daemon-owned control events and canonical subagent record writes
  execution_backend: unchanged
  truth_path: wait, resume, and cancel result envelopes expose canonical
    `receipt_refs` without duplicate `receiptRefs` compatibility aliases
  projection_path: compositor conformance scopes the lifecycle result envelope
    methods and rejects duplicate camelCase receipt aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects duplicate `receiptRefs` aliases in
    wait/resume/cancel lifecycle result envelopes
  - focused daemon tests prove lifecycle result envelopes preserve canonical
    `receipt_refs` and omit retired `receiptRefs`
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare lifecycle
    result `receipt_refs` against the emitted event receipts
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical writes, envelopes, helper
      outputs, errors, and lifecycle result envelopes
    - transient lifecycle staging objects still read broader record aliases
      before canonical write/projection filtering
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 173

```yaml
slice: 173
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent post-spawn lifecycle staging aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent wait, input, resume, assign, and
    cancel staging records before event construction and write filtering
  authority_gate: unchanged; post-spawn lifecycle operations still flow through
    daemon-owned control events and canonical subagent persistence
  execution_backend: unchanged
  truth_path: post-spawn lifecycle staging records expose canonical snake_case
    fields before event payload materialization and canonical write filtering
  projection_path: compositor conformance scopes the five `updated` staging
    object literals and rejects duplicate camelCase record-output aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance counts the five post-spawn lifecycle staging records
    and rejects retired record-output aliases inside them
  - focused daemon tests capture event construction inputs and prove wait,
    input, resume, assign, cancel, and propagated cancel staging records are
    canonical before event payload construction
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare
    pre-event lifecycle staging records against the canonical record-output
    alias filter
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent spawn still builds a broader transient compatibility
      record before canonical write/projection filtering
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical post-spawn lifecycle
      staging records, writes, envelopes, helpers, errors, and result envelopes
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 174

```yaml
slice: 174
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent spawn staging aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent spawn staging record before event
    construction and write filtering
  authority_gate: unchanged; spawn still flows through daemon-owned child agent
    creation, run creation, control event emission, and canonical persistence
  execution_backend: unchanged
  truth_path: spawn staging records expose canonical snake_case fields before
    event payload materialization and canonical write filtering
  projection_path: compositor conformance scopes the spawn `record` staging
    object literal and rejects duplicate camelCase record-output aliases
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance scopes the spawn staging record and rejects retired
    record-output aliases inside it
  - focused daemon tests capture spawn event construction inputs and prove
    successful and budget-blocked spawn staging records are canonical before
    event payload construction
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare
    pre-event spawn staging records against the canonical record-output alias
    filter
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still accepts broader camelCase request and raw
      record input fields while producing canonical spawn and post-spawn
      lifecycle staging records, writes, envelopes, helpers, errors, and result
      envelopes
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 175

```yaml
slice: 175
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent control-event record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent control event construction
  authority_gate: unchanged; control events still emit only through
    daemon-owned subagent lifecycle operations
  execution_backend: unchanged
  truth_path: control event construction reads canonical record fields for
    event hash, turn/item identity, workflow fallback, and budget policy refs
  projection_path: compositor conformance scopes `appendThreadSubagentControlEvent`
    and rejects retired camelCase record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.subagentId`, `record.parentTurnId`,
    workflow, and budget camelCase record fallbacks inside control event
    construction
  - focused daemon tests pass retired camelCase record aliases into the helper
    and prove emitted event identity, workflow fallback, and policy refs ignore
    them
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare control
    event output against canonical record/default fields when retired aliases
    are present
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent control event construction still accepts broader
      camelCase request fields for route compatibility
    - runtime subagent surface still reads broader raw record aliases in lookup,
      result, lifecycle, assignment, and propagation paths until those are
      separately retired
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 176

```yaml
slice: 176
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent list/get persisted record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent list and lookup read paths
  authority_gate: unchanged; list/get remain read-only daemon projection helpers
  execution_backend: unchanged
  truth_path: list and lookup now accept only canonical persisted
    `parent_thread_id` and `created_at` fields for thread membership and order
  projection_path: compositor conformance scopes list/get blocks and rejects
    retired camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.parentThreadId` and `createdAt`
    fallbacks inside subagent list/get read paths
  - focused daemon tests pass poisoned `parentThreadId` and `createdAt`
    aliases into stored records and prove list/get behavior follows canonical
    persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare list
    membership and lookup behavior against canonical persisted fields when
    retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent list still accepts broader camelCase option aliases at
      the API boundary
    - runtime subagent surface still reads broader raw record aliases in
      result, lifecycle, assignment, and propagation paths until those are
      separately retired
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 177

```yaml
slice: 177
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent cancellation-propagation record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent cancellation propagation
  authority_gate: unchanged; propagated cancels still flow through daemon-owned
    subagent cancel operations
  execution_backend: unchanged
  truth_path: propagation candidate selection, ordering, target id, inheritance,
    and lifecycle checks now read canonical persisted record fields only
  projection_path: compositor conformance scopes propagation and rejects retired
    camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.parentThreadId`, `record.subagentId`,
    `record.agentId`, `record.cancellationInheritance`, `record.lifecycleStatus`,
    and `createdAt` fallbacks inside cancellation propagation
  - focused daemon tests poison those retired aliases and prove propagation
    follows canonical persisted fields for candidate count, skipped ordering,
    and cancellation output
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare
    propagated-cancel candidate membership, skip order, and saved cancellation
    output against canonical persisted fields when retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent propagation still creates broader camelCase request fields
      for the downstream cancel request until request-shape aliases are retired
    - runtime subagent surface still reads broader raw record aliases in result,
      lifecycle, and assignment paths until those are separately retired
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 178

```yaml
slice: 178
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent wait/result record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent wait and result read paths
  authority_gate: unchanged; wait/result remain daemon-owned lifecycle and
    projection helpers
  execution_backend: unchanged
  truth_path: wait/result read canonical persisted `run_id`,
    `output_contract`, and `lifecycle_status` fields only
  projection_path: compositor conformance scopes wait/get-result blocks and
    rejects retired camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.runId`, `record.outputContract`,
    `record.lifecycleStatus`, and intermediate `outputContractStatus` aliases
    inside wait/get-result read paths
  - focused daemon tests poison those retired aliases and prove wait/result
    status, run output, and output-contract validation follow canonical
    persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare wait and
    result projections against canonical persisted run/output-contract/status
    fields when retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still reads broader raw record aliases in
      send-input, resume, assign, and cancel lifecycle paths until those are
      separately retired
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 179

```yaml
slice: 179
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent send-input record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent send-input lifecycle
  authority_gate: unchanged; send-input still emits through daemon-owned
    subagent lifecycle event construction
  execution_backend: unchanged
  truth_path: send-input reads canonical persisted status, run, agent,
    output-contract, input-history, previous-run, and evidence fields only
  projection_path: compositor conformance scopes send-input and rejects retired
    camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.lifecycleStatus`, `record.runId`,
    `record.agentId`, `record.outputContract`, `record.inputHistory`,
    `record.previousRunIds`, and `updated.evidenceRefs` inside send-input
    lifecycle handling
  - focused daemon tests poison those retired aliases and prove send-input
    status, child-agent routing, output-contract validation, input history,
    previous-run refs, and evidence refs follow canonical persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare
    send-input saved records and created run metadata against canonical
    persisted fields when retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still reads broader raw record aliases in resume,
      assign, and cancel lifecycle paths until those are separately retired
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 180

```yaml
slice: 180
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent resume record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent resume lifecycle
  authority_gate: unchanged; resume still emits through daemon-owned subagent
    lifecycle event construction
  execution_backend: unchanged
  truth_path: resume reads canonical persisted run, status, agent, model-route,
    output-contract, restart-count, resume-history, cancellation-history,
    previous-run, and evidence fields only
  projection_path: compositor conformance scopes resume and rejects retired
    camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.runId`, `record.lifecycleStatus`,
    `record.agentId`, `record.modelRouteId`, `record.outputContract`,
    `record.restartCount`, `record.resumeHistory`,
    `record.cancellationHistory`, `record.previousRunIds`, and
    `updated.evidenceRefs` inside resume lifecycle handling
  - focused daemon tests poison those retired aliases and prove resume
    previous-status, child-agent routing, model route, output-contract
    validation, restart count, histories, previous-run refs, and evidence refs
    follow canonical persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare resume
    saved records and created run metadata against canonical persisted fields
    when retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still reads broader raw record aliases in assign
      and cancel lifecycle paths until those are separately retired
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 181

```yaml
slice: 181
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent assign record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent assign lifecycle
  authority_gate: unchanged; assign still emits through daemon-owned subagent
    lifecycle event construction
  execution_backend: unchanged
  truth_path: assign reads canonical persisted tool-pack, model-route,
    merge-policy, cancellation-inheritance, agent, assignment-count,
    assignment-history, run, output-contract, and evidence fields only
  projection_path: compositor conformance scopes assign and rejects retired
    camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.toolPack`, `record.modelRouteId`,
    `record.mergePolicy`, `record.cancellationInheritance`, `record.agentId`,
    `record.assignmentCount`, `record.assignmentHistory`, `record.runId`,
    `record.outputContract`, and `updated.evidenceRefs` inside assign lifecycle
    handling
  - focused daemon tests poison those retired aliases and prove assign target,
    tool pack, model route, merge/cancellation policy, assignment count/history,
    run result, output-contract validation, and evidence refs follow canonical
    persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare assign
    saved records and result metadata against canonical persisted fields when
    retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - runtime subagent surface still reads broader raw record aliases in cancel
      lifecycle paths until separately retired
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 182

```yaml
slice: 182
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent cancel record alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent cancel lifecycle
  authority_gate: unchanged; cancel still emits through daemon-owned subagent
    lifecycle event construction
  execution_backend: unchanged
  truth_path: cancel reads canonical persisted lifecycle status, run,
    output-contract, budget, usage telemetry, and evidence fields only
  projection_path: compositor conformance scopes cancel and rejects retired
    camelCase persisted record-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `record.lifecycleStatus`, `record.runId`,
    `record.outputContract`, `updated.evidenceRefs`, and direct persisted-record
    `subagentBudgetForRequestDep(record)` inspection inside cancel lifecycle
    handling
  - focused daemon tests poison those retired aliases and prove cancel previous
    status, canceled run, output-contract validation, run receipts, and evidence
    refs follow canonical persisted fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare cancel
    saved records, run state, and result metadata against canonical persisted
    fields when retired aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 183

```yaml
slice: 183
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent persisted budget request-alias reads
owner_boundary:
  route_or_surface: runtime-daemon subagent send-input and resume lifecycle
  authority_gate: unchanged; send-input and resume still emit through
    daemon-owned subagent lifecycle event construction
  execution_backend: unchanged
  truth_path: send-input and resume budget lookup read canonical persisted
    `budget` only and no longer pass full records through request-shape helpers
  projection_path: compositor conformance scopes send-input and resume and
    rejects persisted-record request-budget helper alias inspection
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects `subagentBudgetForRequestDep(record)` inside
    send-input and resume lifecycle handling
  - focused daemon tests poison retired persisted `subagentBudget` aliases while
    canonical `budget` remains within policy and prove lifecycle writes stay
    within budget
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare
    send-input and resume budget status against canonical persisted budget when
    retired request-budget aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request-shape camelCase aliases remain pending at the API boundary
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 184

```yaml
slice: 184
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent control-event request aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent lifecycle event construction
  authority_gate: unchanged; lifecycle operations still emit daemon-owned
    control events through the same event construction boundary
  execution_backend: unchanged
  truth_path: control-event construction reads canonical request
    `workflow_graph_id`, `workflow_node_id`, `receipt_refs`,
    `policy_decision_refs`, and `idempotency_key` only
  projection_path: compositor conformance scopes control-event construction and
    rejects retired camelCase request-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects request `workflowGraphId`,
    `workflowNodeId`, `receiptRefs`, `policyDecisionRefs`, and `idempotencyKey`
    reads inside lifecycle event construction
  - focused daemon tests poison those retired request aliases and prove event
    workflow metadata, receipt refs, policy refs, and idempotency key follow
    canonical request fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare emitted
    lifecycle event metadata against canonical request fields when retired
    request aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request-shape camelCase aliases remain pending in operation-specific
      subagent request parsing
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Implementation Slice 185

```yaml
slice: 185
phase: 10-authoritative-js-facade-retirement
objective: retire runtime subagent spawn request aliases
owner_boundary:
  route_or_surface: runtime-daemon subagent spawn lifecycle
  authority_gate: unchanged; spawn still emits through daemon-owned subagent
    lifecycle event construction
  execution_backend: unchanged
  truth_path: spawn reads canonical request shape for prompt, role,
    concurrency, tool pack, model route, output contract, workflow metadata,
    context-pressure metadata, source refs, merge policy, and cancellation
    inheritance
  projection_path: compositor conformance scopes spawn and rejects retired
    camelCase request-alias reads
touched_files:
  docs:
    - docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md
  daemon:
    - packages/runtime-daemon/src/runtime-subagent-surface.mjs
    - packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
  tests:
    - scripts/conformance/hypervisor-conformance.mjs
conformance_checks:
  - compositor conformance rejects spawn request `subagentPrompt`,
    `subagentRole`, `maxConcurrency`, `modelRouteId`, `outputContract`,
    `workflowGraphId`, `workflowNodeId`, `parentTurnId`, `contextPressure`,
    `receiptRefs`, `policyDecisionRefs`, `toolPack`, `forkContext`,
    `mergePolicy`, and `cancellationInheritance` alias reads
  - focused daemon tests poison those retired request aliases and prove spawn
    record metadata, created run prompt, lifecycle event refs, and evidence refs
    follow canonical request fields only
verification:
  commands:
    - node --check scripts/conformance/hypervisor-conformance.mjs
    - node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs
    - npm run hypervisor-conformance:compositor
    - npm run hypervisor-conformance
    - git diff --check
  replay_or_shadow_comparison: runtime subagent surface tests compare spawned
    record/event/run metadata against canonical request fields when retired
    request aliases disagree
cleanup:
  legacy_paths_removed: true
  compatibility_shims_remaining:
    - request-shape camelCase aliases remain pending in non-spawn subagent
      lifecycle request parsing
closeout:
  git_diff_check: required
  commit: required
  push: required after verification
```

## Route-Family Owner Map

| Route family | Current live anchor | Current owner | Final owner | Truth path target | Conformance tier | Current status | Deletion or demotion condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `coding-tools` | `packages/runtime-daemon/src/coding-tools.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `packages/runtime-daemon/src/step-module-runner.mjs`, `packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs`, `crates/node/src/bin/ioi-step-module-bridge.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | Rust workload live execution for every current coding tool: workspace.status, git.diff, file.inspect, file.apply_patch, test.run, lsp.diagnostics, artifact.read, tool.retrieve_result, and computer_use.request_lease; JS retains only tool catalog/schema/result/range/summary helper code as non-authoritative protocol support | Rust core `step_router` plus workload/WASM backend | Agentgres admitted operation with receipt, refs, heads, and state roots | `abi`, `bridge`, `receipts`, `negative` | every current coding-tool ID returns a Rust live payload; coding-tool Step/Module projections default to `workload_job` / `workload_grpc`; `createStepModuleRunnerFromEnv` defaults to `rust_workload_live`; explicit `daemon_js` runner selection fails closed; non-live coding-tool runner attempts fail before materialization, command-stream emission, workspace snapshot preparation, or JS tool-body execution; `executeCodingTool` is no longer exported, imported, injected, or accepted by bridge conformance; private JS implementation bodies and their process/filesystem imports are removed from the catalog module; coding-tool budget block responses now emit canonical `budget_usage_telemetry` without duplicate `budgetUsageTelemetry` | Rust path passes shadow, gated, and live parity for each migrated tool; JS can no longer append authoritative effects. |
| `approvals-gates` | `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `crates/services/src/agentic/runtime/kernel/authority.rs` | JS daemon routes plus Rust external-exit authority guard | Rust core `authority` with wallet.network handoff | authority grant and approval receipt before effect boundary | `bridge`, `negative` | Rust wallet.network guard implemented for external exits; live JS approval surface remains | JS can only request/render approvals; grants and gate decisions are issued by Rust authority core and wallet.network. |
| `runtime-events-replay-trace` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `packages/runtime-daemon/src/runtime-event-payloads.mjs`, `packages/runtime-daemon/src/runtime-usage-events.mjs`, `packages/runtime-daemon/src/usage-telemetry.mjs`, `packages/runtime-daemon/src/threads/context-budget-policy.mjs`, `packages/runtime-daemon/src/subagent-manager.mjs`, `packages/runtime-daemon/src/runtime-subagent-surface.mjs`, `packages/runtime-daemon/src/runtime-http-utils.mjs`, `packages/runtime-daemon/src/runtime-mcp-helpers.mjs`, `packages/runtime-daemon/src/threads/thread-replay.mjs`, `packages/runtime-daemon/src/threads/thread-turn-projection.mjs`, `packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs`, `packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs`, `packages/runtime-daemon/src/runtime-record-projections.mjs`, `packages/runtime-daemon/src/runtime-run-read-surface.mjs`, `packages/runtime-daemon/src/index.mjs`, `packages/agent-sdk/src/runtime-events.ts`, `packages/agent-sdk/src/substrate-client.ts` | JS daemon envelope/projection code with the legacy run-event read alias, legacy runtime-event payload id/type aliases, usage/context-pressure payload summary `eventKind` aliases, usage/context-pressure producer camelCase aliases, usage/context-pressure summary reader camelCase aliases, runtime usage telemetry output aliases, runtime usage event telemetry input aliases, runtime usage telemetry reader aliases, thread/turn usage projection aliases, runtime bridge turn usage result aliases, runtime agent run lifecycle usage aliases, runtime bridge run record usage aliases, monolithic daemon run/trace usage aliases, context-budget usage telemetry input aliases, subagent budget usage telemetry input aliases, subagent previous-usage telemetry output aliases, subagent run-usage telemetry output aliases, subagent result output aliases, subagent manager event payload output aliases, subagent manager event payload input aliases, dead SDK mock-envelope cursor helpers, daemon runtime-event envelope output aliases, runtime subagent budget/usage telemetry output aliases, runtime subagent usage telemetry input alias, subagent manager usage telemetry projection alias, runtime subagent record projection output aliases, and MCP serve-result event-id alias fallback retired | Rust core `projection` plus Agentgres projection watermarks | replayable projection over admitted operations and receipts | `receipts`, `compositor` | JS projection source; daemon run reads now expose canonical replay/projection methods without `legacyEventsForRun`; SDK event typing derives from canonical `event_kind` instead of legacy payload type aliases; usage and context-pressure payload summaries emit canonical `event_kind` without duplicate `eventKind`; usage and context-pressure producer payloads emit canonical snake_case fields without camelCase duplicates; runtime payload summaries ignore retired camelCase usage/context-pressure data aliases; runtime usage telemetry run/thread/list/summary producers emit canonical snake_case fields without camelCase duplicates; runtime usage event delta producers ignore retired camelCase telemetry input aliases; runtime usage telemetry run/thread/subagent/aggregate/summary readers ignore retired camelCase telemetry input data aliases; thread/turn projections no longer emit `usageTelemetry`, `runtimeUsage`, or `runtime_usage` compatibility fields and turn usage ignores legacy-only run usage aliases; runtime bridge turn normalization ignores retired usage result aliases; extracted runtime agent run lifecycle records no longer emit `usageTelemetry` or `runtimeUsage` on created run/trace records; runtime bridge run/trace projections and trace artifacts no longer emit `usageTelemetry` or `runtimeUsage`; monolithic daemon run/trace assembly no longer reads or emits retired usage aliases and now passes canonical `model_route_decision` into usage telemetry; context-budget policy reads canonical usage telemetry inputs only and ignores retired request/data aliases before policy evaluation; subagent budget policy reads canonical usage telemetry inputs only and ignores retired request/data/model-route aliases before policy evaluation; subagent previous-usage telemetry normalizer and run-usage telemetry helper emit canonical snake_case fields without duplicate camelCase aliases; subagent result envelopes expose canonical snake_case output fields without duplicate camelCase aliases; subagent manager event payloads expose canonical snake_case identity, lifecycle, budget, usage, receipt, policy, cost, and token fields without duplicate camelCase aliases, IDE/SDK raw payload proofs consume canonical keys, and the event payload helper ignores retired camelCase-only record inputs; runtime subagent records emit canonical `budget_usage_telemetry` and `usage_telemetry` without duplicate `budgetUsageTelemetry`/`usageTelemetry`; runtime subagent budget evaluation ignores retired record `usageTelemetry` fallback; runtime subagent record projections expose canonical snake_case fields without duplicate camelCase aliases; subagent manager result/event projections emit canonical `usage_telemetry` without duplicate `usageTelemetry` and ignore retired `usageTelemetry` inputs; SDK runtime-event module no longer exposes dead mock envelope builders or a noncanonical `event.id` cursor fallback; daemon normalized envelopes no longer emit duplicate top-level `id`, `event`, or `timestamp_ms`; SSE/replay cursors use canonical `event_id`; MCP serve results ignore retired `event.id` aliases and expose only canonical runtime `event_id` | Rust emits canonical projection records consumed by IDE/CLI/SDK. |
| `model-mounting` | `packages/runtime-daemon/src/model-mounting/*`, `packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/model_mount.rs` | JS daemon model-mounting store/provider control surfaces plus extracted JS receipt-write guard policy, Rust route-decision, provider-execution, fixture and native-local non-stream provider-invocation execution, native-local stream invocation planning/chunks, local-provider health/load/unload lifecycle result-envelope planning with provider-health receipt guards and fail-closed local provider start/stop control, local-provider model/list-loaded inventory result-envelope planning with provider-inventory lifecycle-receipt guards, migrated local-provider model-instance lifecycle transition planning for load/unload/evict/supersede with direct-write and provider-kind-bound lifecycle-receipt guards, provider-result admission for non-migrated driver and stream-start observations, invocation-receipt admission, receipt_binder binding, Agentgres admission for invocation and stream-completion receipts, canonical snake_case route-decision receipt/projection/native-response details, provider-lifecycle, provider-inventory, instance-lifecycle, admission, and receipt-binding detail guards, retired hosted-fallback policy alias, retired route-decision fallback request aliases, retired provider-open retry, wallet authority audit, vault audit, receipt-store, OpenAI provider stream-shape operation-like appends, stale daemon append callback injection, retired legacy model-list facade naming, and guards against unbound direct invocation and model lifecycle receipt appends | Rust core `model_mount` | model invocation receipts, provider-execution/invocation/result receipts, route/custody refs, Agentgres operation | `abi`, `bridge`, `receipts`, `ctee` | live route-selection, provider-execution admission, fixture and native-local non-stream provider invocation execution, native-local stream frame planning/chunks, fixture and native-local health/load/unload lifecycle result envelope planning, fixture and native-local model/list-loaded inventory result envelope planning, migrated local-provider model load/unload/evict/supersede instance lifecycle transition planning, non-migrated provider-result admission for hosted/non-migrated non-stream and stream-start observations, and model-invocation receipts call Rust model_mount; route selection now honors only canonical `allow_hosted_fallback` for hosted fallback policy, ignores the retired `allowHostedFallback` alias, and route-decision fallback metadata is admitted only from canonical `fallback_triggered`/`fallback_reason`; direct JS local provider non-stream `invoke()` and native-local stream production shims now fail closed, dead native-local JS stream helper exports are removed, the obsolete JS native-local output wrapper is deleted, and retired JS native fixture response modules are gone; the provider-invocation bridge now uses the shared `execute_model_mount_provider_invocation` operation instead of a fixture-only command; native-local stream invocations use `execute_model_mount_provider_stream_invocation` and JS only adapts returned Rust chunks into the protocol stream facade; fixture and native-local health/load/unload calls use `plan_model_mount_provider_lifecycle` while JS still supervises process state and persists provider/model-instance lifecycle receipts; direct migrated local-provider `provider_health` receipt writes now fail closed without provider kind and Rust lifecycle action/status/hash/evidence under canonical snake_case provider-lifecycle binding fields through the extracted receipt-write guard module; migrated local-provider `provider_start`/`provider_stop` now fail closed without Rust lifecycle binding, and direct store writes for those receipts require the same canonical snake_case provider-lifecycle binding; fixture and native-local listModels/listLoaded calls use `plan_model_mount_provider_inventory` while JS still reads state records; migrated local provider `loadModel`/`unloadModel` calls and idle-evict/supersede transitions use `plan_model_mount_instance_lifecycle` before JS writes model-instance state, and model-instance state stores the Rust provider lifecycle hash as `model_mount_provider_lifecycle_hash` instead of the retired `providerLifecycleHash` alias; direct migrated local-provider `model-instances` map writes now fail closed without Rust provider-lifecycle hash plus instance lifecycle action/status hashes and evidence under canonical snake_case binding fields; direct migrated local-provider model lifecycle receipt helper and store writes now fail closed without provider kind, canonical provider-lifecycle hash, and the same Rust instance-lifecycle binding; direct migrated local-provider provider-inventory receipt writes now fail closed without provider kind and Rust inventory action/status/hash/evidence under canonical snake_case provider-inventory binding fields through the extracted receipt-write guard module; stream request-shape evidence no longer appends a duplicate JS operation-like record, provider-open retry handling no longer appends a duplicate operation-like retry record, wallet/vault audit mirroring no longer appends local `wallet.*` or `vault.*` operation-like records, receipt persistence no longer appends duplicate daemon operation-log records or exposes the old `operationCount`/`operation-log.jsonl` reader, OpenAI provider stream-shape evidence is bound into stream-completion receipts instead of appended as duplicate operation-like truth, and the runtime store no longer injects daemon-local `appendOperation` into `ModelMountingState` after Rust binding/admission; model-mounting local heads and projection watermarks now derive from persisted receipt count, and the local adapter identifies as a receipt/projection store rather than a local operation-log authority; native stream requests now fail closed before or after stream-start admission instead of downgrading into non-stream invocation; OpenAI-compatible `responses` calls now fail closed instead of translating to chat-completions provider results; provider compatibility-translation markers now fail closed before provider-result admission and no longer enter accepted receipts or native responses; protocol response helpers are no longer re-exported through the broad model-mounting compatibility facade; public model listing now calls `runtimeModelCatalogList` instead of the retired `legacyModelList` facade name; invocation and stream-completion receipts are represented as `model_mount` StepModule results and bound by Rust receipt_binder plus Rust Agentgres admission before JS store persistence; route-decision receipt/projection/native-response details, provider-lifecycle, provider-inventory, instance-lifecycle, admission, accepted receipt-binding, StepModule, Agentgres, and projection detail fields now use canonical snake_case names only, and legacy camelCase `modelMount*`/`modelRouteDecision*` binding details fail closed in the direct store guard, are ignored by projection/response adapters, or are rejected by bridge conformance; direct JS store append of unbound invocation receipts now fails closed through the extracted guard module; hosted/non-migrated request/response/load/unload and stream transports, local provider state-record reads, native-local process supervision/logging, non-migrated lifecycle receipt persistence, and broader JS store demotion still remain | Rust records route decisions, provider execution admission, migrated provider invocation execution, native-local stream invocation chunks, local-provider lifecycle and inventory result envelopes, migrated local-provider model-instance lifecycle transitions, admitted non-migrated provider observations, stream-start observations, and receipts; JS provider/store surfaces are demoted as each remaining provider backend moves behind Rust workload/model_mount execution ownership. |
| `agentgres-admission` | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs`, `.ioi/agentgres` local state, `crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`, `docs/architecture/components/agentgres/*` | daemon-local operation-like records plus Rust admission/storage guards; memory record/policy, runtime-bridge turn budget/error, agent delete, agent/subagent persistence, and run persistence operation mirroring retired; run-state persistence now sends only the run payload, operation kind, storage backend, and canonical projection through the Rust Agentgres commit command, where Rust derives prior heads/state roots, projection watermark, refs, runtime run/task hashes, runtime task/job/checklist materializations, storage admissions, and durable writes; model invocation and stream-completion receipt operations now enter Rust Agentgres admission and unbound direct store appends are rejected | Rust core `agentgres_admission` | expected heads, state-root validation, accepted operation admission | `receipts`, `negative` | Rust operation admission and storage-write guards implemented; Rust runtime-state commit now derives expected heads, state_root_before, run_state_hash, task_state_hash, state_root_after, resulting_head, projection watermark, transition hash, materialized run/task/job/checklist/sidecar/projection records, content hashes, object refs, PayloadRefs, storage admissions, write-set hash, persistence hash, commit hash, and Rust-written local JSON records from one JS commit request; the runtime-daemon JS facade and Rust command bridge no longer expose lower-level transition planning, materialization, storage-write-set, or persistence methods as execution entry points; runtime Agentgres admission requires `IOI_RUNTIME_AGENTGRES_COMMAND` and no longer reuses the model-mount command env as a fallback; model invocation and stream-completion receipt operations carry expected-head/state-root admission; direct unbound invocation receipt store writes fail closed; memory record/policy updates no longer mirror `memory.*` operation-log records; runtime bridge turn submits no longer mirror budget/error operation records; guarded agent deletion no longer mirrors `agent.delete`; agent/subagent record writes no longer append operation-log mirrors; run persistence no longer appends operation-log records and now leaves prior transition lookup to Rust commit; runtime read, doctor, tool, and turn projection surfaces no longer expose the daemon-local operation log | no JS path can append accepted operations directly or mutate durable truth without expected heads/state-root binding and storage ArtifactRef/PayloadRef admission. |
| `receipt-binding` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/ipc/proto/public/v1/public.proto`, `crates/services/src/agentic/runtime/kernel/receipt_binder.rs` | JS receipts plus Rust receipt binder and append guard | Rust core `receipt_binder` | one binder for invocation, result, artifact refs, payload refs, and state roots | `receipts`, `negative` | binder primitive and direct-append guard implemented; JS receipts still live | every meaningful route family emits receipts through one Rust binder. |
| `ctee-private-workspace` | `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`, `crates/services/src/agentic/runtime/kernel/ctee.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs`, `packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs`, `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `packages/runtime-daemon/src/index.mjs`, `packages/agent-sdk/src/substrate-client.ts`, `packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts`, `crates/cli/src/commands/runtime.rs` | canon plus Rust StepModule validation, execution, receipt-binding, Agentgres admission, projection bundle, daemon command bridge exposure, mounted daemon runner, product/API cTEE action route, and SDK/IDE/CLI admission clients | Rust core `ctee` | custody proof, leakage profile, declassification receipt, plaintext-free mount failure | `ctee`, `negative` | Rust validation and execution/admission/projection bundle implemented and exposed through `execute_private_workspace_ctee_action`; daemon `RustCteePrivateWorkspaceRunner` now calls that bridge and is mounted on `AgentgresRuntimeStateStore`; `POST /v1/threads/{thread_id}/ctee-private-workspace-actions` executes/admits cTEE actions through the mounted runner without a JS apply shortcut; SDK `executeCteePrivateWorkspaceAction`, IDE cTEE private workspace control nodes, and CLI `runtime ctee-private-workspace execute` consume that route without minting accepted truth directly; deeper private workspace UI/replay surfaces still pending | untrusted node plaintext mount fails closed; declassification and private operator paths are receipt-bound. |
| `workload-client-wasm` | `crates/client/src/workload_client/mod.rs`, `crates/vm/wasm/src/lib.rs`, `crates/validator/src/standard/workload/*` | Rust workload/kernel substrate exists below daemon | Rust core `workload_client` plus WASM/service backend | StepModuleResult with workload receipt and state-root binding | `bridge`, `receipts` | substrate exists, not default daemon backend | daemon routes admitted work through StepModuleRunner into Rust/WASM or workload backend. |
| `workflow-compositor` | `packages/agent-ide/src/runtime/*`, `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/services/src/agentic/runtime/kernel/projection.rs` | IDE/daemon projection shaping, with terminal coding-loop run-launch, computer-use replay, mixed runtime panel, typed panel event-id alias fallbacks, legacy model-id capability projection retired, IDE context-budget usage request and hydration edge aliases retired, and IDE coding-tool/subagent budget usage request output aliases retired, plus Rust projection record primitive | Rust core `projection` consumed by IDE/CLI/SDK | projection checkpoints rebuilt from Agentgres admitted truth | `compositor`, `negative` | Rust projection record and accepted-truth guard implemented; terminal coding-loop run launch ignores retired runtime `event.id`/`eventId` aliases while materializing telemetry; computer-use replay timeline ignores raw retired `id` aliases and preserves frame IDs only from canonical `event_id`; mixed IDE panels now use a shared event identity adapter that accepts raw canonical `event_id`/`event_kind` and typed projected IDE `id`/`eventKind` only after projected-shape validation; typed workspace trust, hunk-decision, signed replay, context lifecycle, and worker contribution panels also use that adapter instead of local `event_id`/`id` wrappers; IDE model capability binding no longer mints executable `model-capability:legacy.*` refs or readiness from raw `modelId`; IDE context-budget control nodes now generate canonical `usage_telemetry` daemon requests and ignore retired `runtimeUsageMeter`, `runtimeTelemetrySummary`, and `usageTelemetry` request aliases; IDE telemetry budget-chain materialization now hydrates existing context-budget chains only through canonical `usage_telemetry` usage-to-context edges, not retired `runtimeUsageMeter` edge ports; IDE coding-tool and subagent control request bodies now emit canonical `budget_usage_telemetry` without duplicate `budgetUsageTelemetry`; broader IDE/SDK consumption still pending | compositor cannot create accepted truth directly and only renders/replays canonical projections. |
| `worker-service-packages` | `docs/architecture/foundations/common-objects-and-envelopes.md`, `docs/architecture/domains/aiagent/worker-endpoints.md`, `docs/architecture/domains/sas/service-endpoints.md`, `crates/services/src/agentic/runtime/kernel/marketplace.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs`, `packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs`, `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `packages/runtime-daemon/src/index.mjs`, `packages/agent-sdk/src/substrate-client.ts`, `packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts`, `crates/cli/src/commands/runtime.rs` | target canon plus Rust worker/service package invocation admission primitive over StepModuleRouter, receipt_binder, Agentgres admission, projection, command bridge exposure, mounted daemon runner, product/API admission route, and SDK/IDE/CLI admission clients | Rust core `step_router` plus workload/WASM/AIIP backends | package invocation receipt, authority grant, artifacts, projection | `bridge`, `receipts`, `compositor` | Rust package invocation admission primitive implemented and exposed through `admit_worker_service_package_invocation`; daemon `RustWorkerServicePackageRunner` now calls that bridge and is mounted on `AgentgresRuntimeStateStore`; `POST /v1/threads/{thread_id}/worker-service-package-invocations` admits package invocations through the mounted runner without a JS apply shortcut; SDK `admitWorkerServicePackageInvocation`, IDE worker/service package control nodes, and CLI `runtime worker-service-package admit` consume that route without minting accepted truth directly; AIIP delivery and deeper live package execution UI still pending | service and worker package invocation uses the shared Step/Module ABI. |
| `l1-settlement` | `docs/architecture/foundations/ioi-l1-mainnet.md`, `crates/services/src/agentic/runtime/kernel/settlement.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs`, `packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs`, `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `packages/runtime-daemon/src/index.mjs`, `packages/agent-sdk/src/substrate-client.ts`, `packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts`, `crates/cli/src/commands/runtime.rs` | canon plus Rust trigger guard, command bridge admission primitive, mounted daemon runner, product/API settlement admission route, and IDE/CLI/SDK admission clients | Rust settlement/admission core under daemon-owned execution | sparse public/economic/cross-domain commitment by trigger only | `bridge`, `negative` | Rust trigger guard implemented and exposed through `admit_l1_settlement_attempt`; daemon `RustL1SettlementRunner` now calls that bridge and is mounted on `AgentgresRuntimeStateStore`; `POST /v1/threads/{thread_id}/l1-settlement-attempts` admits triggered settlement attempts through the mounted runner without a JS apply shortcut; SDK `admitL1SettlementAttempt`, IDE L1 settlement control nodes, and CLI `runtime l1-settlement admit` consume that route without minting accepted truth directly or allowing default runtime settlement | L1 settlement attempts without marketplace/public/economic/cross-domain/operator trigger fail closed. |
| `meta-improvement` | `crates/services/src/agentic/runtime/kernel/*`, `crates/services/src/agentic/evolution.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `packages/runtime-daemon/src/runtime-governed-improvement-runner.mjs`, `packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs`, `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `packages/runtime-daemon/src/index.mjs`, `packages/agent-sdk/src/substrate-client.ts`, `packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts`, `crates/cli/src/commands/runtime.rs`, workflow/evaluation docs | partial Rust/IDE signals plus governed runtime-improvement proposal admission primitive, command bridge exposure, mounted non-authoritative daemon runner, product/API proposal admission route, and stable SDK/IDE/CLI review clients requiring eval/verifier receipts, approval, rollback, Agentgres operation refs, expected heads, and state roots; legacy direct `EvolutionService::evolve` manifest mutation now fails closed | Rust core authority plus proposal/eval/approval path | proposal object, eval receipts, approval grant, committed mutation | `bridge`, `receipts`, `negative` | Rust governed proposal admission primitive implemented, exposed through `admit_governed_runtime_improvement_proposal`, reachable via daemon `RustGovernedImprovementRunner`, mounted on `AgentgresRuntimeStateStore`, exposed at `POST /v1/threads/{thread_id}/governed-improvement-proposals`, consumable through SDK `admitGovernedImprovementProposal`, composable from IDE governed-improvement control nodes, and consumable through CLI `runtime governed-improvement admit` without a JS apply shortcut; direct `EvolutionService::evolve` manifest mutation retired; full IDE review UI, rollback application, and live mutation commit path still pending | agents cannot self-modify directly; all improvements are proposal-mediated. |
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

Current expected behavior after Slice 191:

Slice 169 adds compositor proof for
`runtime-subagent-list-propagation-envelope-aliases-retired`: runtime subagent
list and cancellation-propagation envelopes expose canonical snake_case fields
without duplicate camelCase response aliases.

Slice 170 adds compositor proof for
`runtime-subagent-nested-helper-output-aliases-retired`: runtime subagent
input, resume, assignment, and cancellation helper objects expose canonical
snake_case fields without duplicate camelCase response aliases.

Slice 171 adds compositor proof for
`runtime-subagent-error-detail-aliases-retired`: runtime subagent validation and
policy errors expose canonical snake_case detail fields without duplicate
camelCase response aliases.

Slice 172 adds compositor proof for
`runtime-subagent-lifecycle-result-envelope-aliases-retired`: runtime subagent
wait, resume, and cancel result envelopes expose canonical `receipt_refs`
without duplicate `receiptRefs` aliases.

Slice 173 adds compositor proof for
`runtime-subagent-post-spawn-lifecycle-staging-aliases-retired`: runtime
subagent wait, input, resume, assign, cancel, and propagated-cancel staging
records are canonical before event construction and write filtering.

Slice 174 adds compositor proof for
`runtime-subagent-spawn-staging-aliases-retired`: runtime subagent successful
and budget-blocked spawn staging records are canonical before event construction
and write filtering.

Slice 175 adds compositor proof for
`runtime-subagent-control-event-record-aliases-retired`: runtime subagent
control event construction ignores retired camelCase record aliases for event
identity, workflow fallback, and budget policy refs.

Slice 176 adds compositor proof for
`runtime-subagent-list-lookup-record-aliases-retired`: runtime subagent list
and lookup read paths ignore retired camelCase persisted record aliases for
thread membership and ordering.

Slice 177 adds compositor proof for
`runtime-subagent-propagation-record-aliases-retired`: runtime subagent
cancellation propagation ignores retired camelCase persisted record aliases for
candidate membership, ordering, target id, inheritance, and lifecycle status.

Slice 178 adds compositor proof for
`runtime-subagent-wait-result-record-aliases-retired`: runtime subagent wait
and result read paths ignore retired camelCase persisted record aliases for run
identity, output-contract validation, and lifecycle status.

Slice 179 adds compositor proof for
`runtime-subagent-send-input-record-aliases-retired`: runtime subagent
send-input lifecycle handling ignores retired camelCase persisted record aliases
for status, run identity, agent identity, output-contract validation, input
history, previous-run refs, and evidence refs.

Slice 180 adds compositor proof for
`runtime-subagent-resume-record-aliases-retired`: runtime subagent resume
lifecycle handling ignores retired camelCase persisted record aliases for
previous status, run identity, agent identity, model route, output-contract
validation, restart count, histories, previous-run refs, and evidence refs.

Slice 181 adds compositor proof for
`runtime-subagent-assign-record-aliases-retired`: runtime subagent assign
lifecycle handling ignores retired camelCase persisted record aliases for
target agent, tool pack, model route, merge/cancellation policy, assignment
count/history, run result, output-contract validation, and evidence refs.

Slice 182 adds compositor proof for
`runtime-subagent-cancel-record-aliases-retired`: runtime subagent cancel
lifecycle handling ignores retired camelCase persisted record aliases for
previous status, canceled run, output-contract validation, budget lookup, run
receipts, and evidence refs.

Slice 183 adds compositor proof for
`runtime-subagent-budget-record-request-aliases-retired`: runtime subagent
send-input and resume lifecycle budget lookup reads canonical persisted
`budget` only and ignores retired persisted request-budget aliases such as
`subagentBudget`.

Slice 184 adds compositor proof for
`runtime-subagent-control-event-request-aliases-retired`: runtime subagent
lifecycle event construction reads canonical request workflow metadata, receipt
refs, policy refs, and idempotency key only and ignores retired camelCase
request aliases.

Slice 185 adds compositor proof for
`runtime-subagent-spawn-request-aliases-retired`: runtime subagent spawn
lifecycle handling reads canonical request metadata for prompt, role,
concurrency, tool pack, model route, output contract, workflow/context metadata,
refs, merge policy, and cancellation inheritance, and ignores retired camelCase
request aliases.

Slice 186 adds compositor proof for
`runtime-subagent-budget-request-aliases-retired`: shared runtime subagent
budget request parsing reads canonical `budget` / `options.budget` only and
ignores the retired `subagentBudget` request alias before budget policy
evaluation.

Slice 187 adds compositor proof for
`runtime-subagent-list-request-aliases-retired`: runtime subagent list filters
read canonical `role` / `subagent_role` only and ignore the retired
`subagentRole` request alias.

Slice 188 adds compositor proof for
`runtime-subagent-send-input-request-aliases-retired`: runtime subagent
send-input lifecycle handling reads canonical input/workflow request metadata
only and ignores retired camelCase request aliases such as `subagentInput`,
`workflowGraphId`, and `workflowNodeId`.

Slice 189 adds compositor proof for
`runtime-subagent-resume-request-aliases-retired`: runtime subagent resume
lifecycle handling reads canonical role, model route, prompt, and workflow
request metadata only and ignores retired camelCase request aliases such as
`subagentRole`, `modelRouteId`, `subagentModelRoute`, `resumePrompt`,
`workflowGraphId`, and `workflowNodeId`.

Slice 190 adds compositor proof for
`runtime-subagent-assign-request-aliases-retired`: runtime subagent assign
lifecycle handling reads canonical role, tool pack, model route, merge policy,
cancellation inheritance, target agent, and workflow request metadata only and
ignores retired camelCase request aliases such as `subagentRole`, `toolPack`,
`subagentToolPack`, `modelRouteId`, `subagentModelRoute`, `mergePolicy`,
`cancellationInheritance`, `targetAgentId`, `workflowGraphId`, and
`workflowNodeId`.

Slice 191 adds compositor proof for
`runtime-subagent-cancel-request-aliases-retired`: runtime subagent cancel
lifecycle handling and propagation wrappers read canonical cancellation reason,
inheritance, and provenance request metadata only and ignore retired camelCase
request aliases such as `cancellationReason`, `cancellationInherited`, and
`propagatedFromThreadId`.

| Command | Expected status now | Reason |
| --- | --- | --- |
| `hypervisor-conformance:docs` | pass | Phase 0 inventory, source map, matrix, command wiring, and stale-term guard exist. |
| `hypervisor-conformance:abi` | pass | Step/Module schemas and current coding-tool projection wrappers exist, and coding-tool projections default to `workload_job` / `workload_grpc` instead of daemon_js. |
| `hypervisor-conformance:bridge` | pass | daemon StepModuleRunner boundary defaults to Rust workload live, explicit `daemon_js` backend selection fails closed, runtime coding-tool invocation requires Rust workload live, the retired JS `executeCodingTool` dispatcher is no longer present in the invocation surface, catalog module export surface, or daemon constructor injection, private JS coding-tool implementation bodies and their process/filesystem imports are absent from `coding-tools.mjs`, coding-tool budget block responses emit canonical `budget_usage_telemetry` without duplicate `budgetUsageTelemetry`, live Rust model_mount provider-execution admission bridge, shared Rust provider invocation bridge for fixture and native-local non-stream execution, Rust native-local stream invocation bridge and returned-chunk adapter, Rust local-provider lifecycle planner bridge for fixture/native-local health/load/unload result envelopes, Rust local-provider inventory planner bridge for fixture/native-local model/list-loaded result envelopes, Rust instance lifecycle bridge for migrated local-provider model load/unload/evict/supersede state transitions emits `provider_lifecycle_hash` without the retired `providerLifecycleHash` alias, model-mount route-decision receipt/projection/native-response details, provider-lifecycle, provider-inventory, instance-lifecycle, admission, and receipt-binding details now use canonical snake_case fields at the bridge-facing receipt boundary, hosted fallback policy, runtime thread-control policy helpers, and SDK/IDE policy helper types use canonical `allow_hosted_fallback` without the retired `allowHostedFallback` alias, route-decision fallback request metadata uses canonical `fallback_triggered`/`fallback_reason` without retired camelCase alias reads, IDE model capability binding no longer mints executable `model-capability:legacy.*` refs or readiness from raw `modelId`, retired direct JS local provider non-stream invoke and native-local stream production shims, removed dead native-local stream helper exports, obsolete output wrapper, retired fixture response modules, Rust provider-result admission bridge, stream-start provider-result admission guard, native-stream no-downgrade guards, OpenAI-compatible responses no-fallback guard, provider compatibility-translation fail-closed guard, protocol response facade re-export retirement guard, legacy model-list facade naming retirement guard, worker/service package invocation admission bridge, fail-closed daemon worker-service package runner mounted on the runtime store, product/API worker-service package invocation route, SDK/IDE/CLI worker-service package admission clients, cTEE Private Workspace CLI action client, L1 settlement admission bridge, fail-closed daemon L1 settlement runner mounted on the runtime store, product/API L1 settlement admission route, IDE/CLI/SDK L1 settlement admission clients, governed meta-improvement proposal admission bridge, fail-closed daemon governed-improvement runner mounted on the runtime store, product/API governed-improvement proposal admission route, and SDK/IDE/CLI governed-improvement proposal clients exist without a duplicate JS request-shape append or JS apply shortcut. |
| `hypervisor-conformance:receipts` | pass | Rust StepModule receipt binder exists, model provider execution is admitted before driver calls, fixture and native-local non-stream provider invocation execute in Rust, native-local stream frame planning/chunks execute in Rust, local-provider health/load/unload lifecycle status/backend/evidence envelopes are planned and hash-bound in Rust, local-provider model/list-loaded inventory status/backend/evidence envelopes are planned and hash-bound in Rust, migrated local-provider model load/unload/evict/supersede instance lifecycle transitions are planned and hash-bound in Rust to provider lifecycle hashes, direct migrated local-provider model-instance map and lifecycle receipt helper/store persistence without provider kind, canonical provider-lifecycle hash, and Rust instance lifecycle action/status hashes now fails closed under canonical snake_case binding fields, direct migrated local-provider provider-health receipt persistence without provider kind and Rust lifecycle action/status/hash/evidence now fails closed under canonical snake_case provider-lifecycle binding fields, migrated local-provider provider start/stop fails closed without Rust lifecycle binding and direct provider-control receipt persistence requires the same canonical snake_case provider-lifecycle binding, direct migrated local-provider provider-inventory receipt persistence without provider kind and Rust inventory action/status/hash/evidence now fails closed under canonical snake_case provider-inventory binding fields, the direct receipt-write guards now live outside the JS store adapter in `model-mounting/receipt-write-guards.mjs`, model route-decision and invocation receipt-binding guards require canonical snake_case receipt_binder/Agentgres/StepModule detail fields and reject legacy camelCase `modelMount*` binding details; model-mount admission metadata also uses canonical snake_case detail fields only, non-migrated provider results and native stream-start observations are Rust-admitted observations, runtime run-state persistence sends one commit request to Rust, where Agentgres admission derives prior heads/state roots, projection watermark, receipt/artifact/payload refs, run-state and task-state hashes, runtime task/job/checklist materializations, storage admissions, write-set hash, persistence hash, commit hash, and Rust-written local JSON records; `writeRunRecord` no longer calls JS transition planning, JS persistence, JS materialization, storage write-set planning, or local `writeJson`, and neither the runtime-daemon JS facade nor the Rust command bridge exposes lower-level transition/materialization/storage-write-set/persistence methods as execution entry points, runtime Agentgres admission requires the explicit `IOI_RUNTIME_AGENTGRES_COMMAND` env without model-mount env fallback, stream request-shape evidence, provider-open retry handling, wallet authority audit mirroring, vault audit mirroring, receipt persistence and model-mount local adapter status no longer expose local operation-log terminology or an `operation-log.jsonl` reader, OpenAI provider stream-shape recording, stale model-mounting append callback injection, memory record/policy operation mirroring, runtime bridge turn budget/error mirroring, agent delete operation mirroring, agent/subagent persistence operation mirroring, and run persistence/read-surface operation-log exposure no longer create duplicate JS operation-like records; model-mounting local heads and projection watermarks derive from persisted receipt count; model invocation and stream-completion receipts carry Rust Agentgres admission, direct unbound model invocation store appends fail closed, worker/service package invocation has a Rust admission primitive over StepModuleRouter, receipt_binder, Agentgres admission, and projection, meta-improvement proposals have a governed Rust admission primitive requiring eval/verifier receipts, approval, rollback, and Agentgres binding, and the legacy direct `EvolutionService::evolve` manifest mutation body is retired fail-closed. |
| `hypervisor-conformance:ctee` | pass | Rust cTEE Private Workspace module validation exists, untrusted plaintext custody fails closed, the Rust cTEE action bundle binds receipts, admits Agentgres truth, and emits projection records, the daemon command bridge exposes that bundle through `execute_private_workspace_ctee_action`, the daemon `RustCteePrivateWorkspaceRunner` is mounted fail-closed on the runtime store, the product/API cTEE route calls that runner without a JS apply shortcut, and SDK/IDE cTEE clients consume that route without direct truth creation. |
| `hypervisor-conformance:compositor` | pass | Rust projection records exist, the shadow bridge emits them, compositor accepted-truth attempts fail closed, the daemon run-read facade no longer exposes the legacy event alias beside canonical replay/projection methods, usage/context-pressure payload summaries expose canonical `event_kind` without duplicate `eventKind`, usage/context-pressure producer payloads emit canonical snake_case fields without camelCase duplicates, runtime payload summaries ignore retired camelCase usage/context-pressure data aliases, runtime usage telemetry run/thread/list/summary producers emit canonical snake_case fields without camelCase duplicates, runtime usage event delta producers ignore retired camelCase telemetry input aliases, runtime usage telemetry run/thread/subagent/aggregate/summary readers ignore retired camelCase telemetry input data aliases, thread/turn projections no longer emit or read retired usage telemetry aliases, runtime bridge turn normalization ignores retired usage result aliases, extracted runtime agent run lifecycle records no longer emit retired usage telemetry aliases, runtime bridge run/trace records no longer emit retired usage telemetry aliases, monolithic daemon run/trace assembly no longer reads or emits retired usage telemetry aliases, context-budget policy ignores retired usage request/data aliases before evaluation, subagent budget policy ignores retired usage request/data/model-route aliases before evaluation, subagent previous-usage telemetry normalizer and run-usage telemetry helper emit canonical snake_case fields without duplicate camelCase aliases, subagent result envelopes expose canonical snake_case output fields without duplicate camelCase aliases, subagent manager event payloads expose canonical snake_case fields without duplicate camelCase aliases, consume canonical raw keys, and ignore retired camelCase-only record inputs, runtime subagent records emit canonical `budget_usage_telemetry` and `usage_telemetry` without duplicate `budgetUsageTelemetry`/`usageTelemetry`, runtime subagent budget evaluation ignores retired record `usageTelemetry` fallback, runtime subagent record projections expose canonical snake_case fields without duplicate camelCase aliases, subagent manager result/event projections emit canonical `usage_telemetry` without duplicate `usageTelemetry` and ignore retired `usageTelemetry` inputs, IDE context-budget control nodes emit canonical `usage_telemetry` requests without retired usage request aliases, IDE telemetry budget-chain materialization hydrates canonical `usage_telemetry` usage-to-context edges without retired `runtimeUsageMeter` edge-port checks, IDE coding-tool/subagent control request bodies emit canonical `budget_usage_telemetry` without duplicate `budgetUsageTelemetry`, runtime subagent error details expose canonical snake_case fields without duplicate camelCase aliases, runtime subagent lifecycle result envelopes expose canonical `receipt_refs` without duplicate `receiptRefs`, runtime subagent post-spawn lifecycle and spawn staging records are canonical before event construction and write filtering, runtime subagent control event construction ignores retired camelCase record aliases, runtime subagent list/get read paths ignore retired camelCase persisted record aliases, runtime subagent cancellation propagation ignores retired camelCase persisted record aliases, runtime subagent wait/result read paths ignore retired camelCase persisted record aliases, runtime subagent send-input lifecycle handling ignores retired camelCase persisted record aliases, runtime subagent send-input request handling ignores retired camelCase aliases, runtime subagent resume lifecycle handling ignores retired camelCase persisted record aliases, runtime subagent resume request handling ignores retired camelCase aliases, runtime subagent assign lifecycle handling ignores retired camelCase persisted record aliases, runtime subagent assign request handling ignores retired camelCase aliases, runtime subagent cancel lifecycle handling ignores retired camelCase persisted record aliases, runtime subagent cancel request handling ignores retired camelCase aliases, runtime subagent send-input/resume budget lookup ignores retired persisted request-budget aliases, runtime subagent control event construction ignores retired camelCase request aliases, runtime subagent spawn lifecycle handling ignores retired camelCase request aliases, shared runtime subagent budget request parsing ignores the retired `subagentBudget` alias, and runtime subagent list filters ignore the retired `subagentRole` alias. |
| `hypervisor-conformance:negative` | pass | All required forbidden-path negative fixtures are implemented at the Rust guard level. |
| `hypervisor-conformance` | pass at current tier surface | Current wired tiers pass; terminal migration is still not claimed until live route families are routed through Rust core and JS facade retirement is complete. |
| `npm run build --workspace=@ioi/agent-ide` | pass | Migrated IDE protocol-client helpers and adjacent replay/projection surfaces compile under the current package TypeScript target. |
