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

## Route-Family Owner Map

| Route family | Current live anchor | Current owner | Final owner | Truth path target | Conformance tier | Current status | Deletion or demotion condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `coding-tools` | `packages/runtime-daemon/src/coding-tools.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `packages/runtime-daemon/src/step-module-runner.mjs`, `crates/node/src/bin/ioi-step-module-bridge.rs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | JS daemon tool dispatch with Step/Module projection wrappers plus live Rust paths for every current coding tool: workspace.status, git.diff, file.inspect, file.apply_patch, test.run, lsp.diagnostics, artifact.read, tool.retrieve_result, and computer_use.request_lease | Rust core `step_router` plus workload/WASM backend | Agentgres admitted operation with receipt, refs, heads, and state roots | `abi`, `bridge`, `receipts`, `negative` | every current coding-tool ID returns a Rust live payload without daemon_js in rust_workload_live mode; JS fallback helpers remain only for non-live compatibility until facade retirement | Rust path passes shadow, gated, and live parity for each migrated tool; JS can no longer append authoritative effects. |
| `approvals-gates` | `packages/runtime-daemon/src/runtime-route-handlers.mjs`, `crates/services/src/agentic/runtime/kernel/authority.rs` | JS daemon routes plus Rust external-exit authority guard | Rust core `authority` with wallet.network handoff | authority grant and approval receipt before effect boundary | `bridge`, `negative` | Rust wallet.network guard implemented for external exits; live JS approval surface remains | JS can only request/render approvals; grants and gate decisions are issued by Rust authority core and wallet.network. |
| `runtime-events-replay-trace` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs` | JS daemon envelope/projection code | Rust core `projection` plus Agentgres projection watermarks | replayable projection over admitted operations and receipts | `receipts`, `compositor` | JS projection source | Rust emits canonical projection records consumed by IDE/CLI/SDK. |
| `model-mounting` | `packages/runtime-daemon/src/model-mounting/*`, `packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs`, `packages/runtime-daemon/src/step-module-abi.mjs`, `crates/node/src/bin/ioi_step_module_bridge/mod.rs`, `crates/services/src/agentic/runtime/kernel/model_mount.rs` | JS daemon model-mounting store/provider control surfaces plus Rust route-decision, provider-execution, fixture and native-local non-stream provider-invocation execution, provider-result admission for non-migrated driver and stream-start observations, invocation-receipt admission, receipt_binder binding, Agentgres admission for invocation and stream-completion receipts, and a store guard against unbound direct invocation appends | Rust core `model_mount` | model invocation receipts, provider-execution/invocation/result receipts, route/custody refs, Agentgres operation | `abi`, `bridge`, `receipts`, `ctee` | live route-selection, provider-execution admission, fixture and native-local non-stream provider invocation execution, non-migrated provider-result admission for hosted/non-migrated non-stream and stream-start observations, and model-invocation receipts call Rust model_mount; direct JS local provider non-stream `invoke()` shims now fail closed; the provider-invocation bridge now uses the shared `execute_model_mount_provider_invocation` operation instead of a fixture-only command; stream request-shape evidence no longer appends a duplicate JS operation-like record; native stream requests now fail closed before or after stream-start admission instead of downgrading into non-stream invocation; OpenAI-compatible `responses` calls now fail closed instead of translating to chat-completions provider results; provider compatibility-translation markers now fail closed before provider-result admission and no longer enter accepted receipts or native responses; protocol response helpers are no longer re-exported through the broad model-mounting compatibility facade; invocation and stream-completion receipts are represented as `model_mount` StepModule results and bound by Rust receipt_binder plus Rust Agentgres admission before JS store persistence; direct JS store append of unbound invocation receipts now fails closed; hosted/non-migrated request/response transport, native stream byte/frame transport, local provider health/list/load/unload control surfaces, and broader JS store demotion still remain | Rust records route decisions, provider execution admission, migrated provider invocation execution, admitted non-migrated provider observations, stream-start observations, and receipts; JS provider/store surfaces are demoted as each remaining provider backend moves behind Rust workload/model_mount execution ownership. |
| `agentgres-admission` | `packages/runtime-daemon/src/service/runtime-daemon-service.mjs`, `.ioi/agentgres` local state, `crates/services/src/agentic/runtime/kernel/agentgres_admission.rs`, `docs/architecture/components/agentgres/*` | daemon-local operation-like records plus Rust admission/storage guards; model invocation and stream-completion receipt operations now enter Rust Agentgres admission and unbound direct store appends are rejected | Rust core `agentgres_admission` | expected heads, state-root validation, accepted operation admission | `receipts`, `negative` | Rust operation admission and storage-write guards implemented; model invocation and stream-completion receipt operations carry expected-head/state-root admission; direct unbound invocation receipt store writes fail closed; broad live JS append/write surfaces still need routing/demotion | no JS path can append accepted operations directly or mutate durable truth without expected heads/state-root binding. |
| `receipt-binding` | `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/ipc/proto/public/v1/public.proto`, `crates/services/src/agentic/runtime/kernel/receipt_binder.rs` | JS receipts plus Rust receipt binder and append guard | Rust core `receipt_binder` | one binder for invocation, result, artifact refs, payload refs, and state roots | `receipts`, `negative` | binder primitive and direct-append guard implemented; JS receipts still live | every meaningful route family emits receipts through one Rust binder. |
| `ctee-private-workspace` | `docs/architecture/components/daemon-runtime/private-workspace-ctee.md`, `crates/services/src/agentic/runtime/kernel/ctee.rs` | canon plus Rust StepModule validation boundary | Rust core `ctee` | custody proof, leakage profile, declassification receipt, plaintext-free mount failure | `ctee`, `negative` | Rust validation path implemented; full execution/admission/projection still pending | untrusted node plaintext mount fails closed; declassification and private operator paths are receipt-bound. |
| `workload-client-wasm` | `crates/client/src/workload_client/mod.rs`, `crates/vm/wasm/src/lib.rs`, `crates/validator/src/standard/workload/*` | Rust workload/kernel substrate exists below daemon | Rust core `workload_client` plus WASM/service backend | StepModuleResult with workload receipt and state-root binding | `bridge`, `receipts` | substrate exists, not default daemon backend | daemon routes admitted work through StepModuleRunner into Rust/WASM or workload backend. |
| `workflow-compositor` | `packages/agent-ide/src/runtime/*`, `packages/runtime-daemon/src/runtime-event-envelopes.mjs`, `crates/services/src/agentic/runtime/kernel/projection.rs` | IDE/daemon projection shaping plus Rust projection record primitive | Rust core `projection` consumed by IDE/CLI/SDK | projection checkpoints rebuilt from Agentgres admitted truth | `compositor`, `negative` | Rust projection record and accepted-truth guard implemented; IDE/SDK consumption still pending | compositor cannot create accepted truth directly and only renders/replays canonical projections. |
| `worker-service-packages` | `docs/architecture/foundations/common-objects-and-envelopes.md`, `docs/architecture/domains/aiagent/worker-endpoints.md`, `docs/architecture/domains/sas/service-endpoints.md` | target canon plus service/module concepts | Rust core `step_router` plus workload/WASM/AIIP backends | package invocation receipt, authority grant, artifacts, projection | `bridge`, `receipts`, `compositor` | target only | service and worker package invocation uses the shared Step/Module ABI. |
| `l1-settlement` | `docs/architecture/foundations/ioi-l1-mainnet.md`, `crates/services/src/agentic/runtime/kernel/settlement.rs` | canon plus Rust trigger guard | Rust settlement/admission core under daemon-owned execution | sparse public/economic/cross-domain commitment by trigger only | `negative` | Rust trigger guard implemented; product settlement surfaces still pending | L1 settlement attempts without marketplace/public/economic/cross-domain/operator trigger fail closed. |
| `meta-improvement` | `crates/services/src/agentic/runtime/kernel/*`, workflow/evaluation docs | partial Rust/IDE signals | Rust core authority plus proposal/eval/approval path | proposal object, eval receipts, approval grant, committed mutation | `receipts`, `negative` | target only | agents cannot self-modify directly; all improvements are proposal-mediated. |
| `rust-daemon-core` | target layout in master guide plus `crates/services/src/agentic/runtime/kernel/*` | partial Rust primitives for authority, step_router, cTEE, receipts, Agentgres admission, projection, settlement, Step/Module ABI, model_mount provider-execution admission, fixture and native-local non-stream provider-invocation execution, and provider-result admission for non-migrated driver observations | Rust modules: `authority`, `step_router`, `workload_client`, `model_mount`, `ctee`, `receipt_binder`, `agentgres_admission`, `projection`, `conformance` | one Rust owner for hot-path semantics | all tiers | partial primitives, not extracted as one authoritative core; model_mount now admits provider-execution envelopes before JS provider driver calls, executes migrated fixture and native-local non-stream provider backends, rejects retired direct JS local provider non-stream invokes, and admits non-migrated JS provider results before receipts | hot-path execution, authority, receipt/state-root binding, cTEE, replay, and conformance are owned by Rust core. |
| `js-facade-retirement` | `packages/runtime-daemon/src/*`, `crates/services/src/agentic/runtime/kernel/step_router.rs` | JS is current live daemon implementation, with Rust guard forbidding authoritative daemon_js mutation | non-authoritative product/API/client facade only where useful | stable protocol APIs into Rust core | `negative`, terminal `hypervisor-conformance` | direct JS authoritative mutation guard implemented; model-mounting protocol response compatibility re-export retired; broad live facade retirement still pending | every migrated route family removes or demotes old JS authoritative paths and compatibility shims. |

## Cleanup Targets Found In Phase 0

These are not deletions for Slice 0. They are the long-term cleanup targets that
must be retired as the corresponding route family reaches verified parity:

| Cleanup target | Why it must not be permanent | Removal trigger |
| --- | --- | --- |
| Direct JS coding tool dispatch for consequential effects | It is the current split-brain authoritative execution path. | Each tool has ABI coverage, Rust/WASM or workload execution, receipts/state roots, and compositor parity. |
| Daemon-local operation-like truth outside Rust Agentgres admission | It risks duplicate accepted truth. | Agentgres admission enforces expected heads and state-root binding for meaningful transitions. |
| Receipt emission in multiple owners | Duplicate receipt paths make replay and failure analysis ambiguous. | `receipt_binder` owns all accepted receipt/result binding. |
| Model/provider fallback routes outside daemon-owned model mounting | Earlier parity work established daemon-owned mounting/routing as source of truth. | Rust `model_mount` owns route decisions, provider-execution admission, migrated fixture/native-local non-stream provider invocation execution, non-migrated provider-result admission, and receipts. |
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

Current expected behavior after Slice 44:

| Command | Expected status now | Reason |
| --- | --- | --- |
| `hypervisor-conformance:docs` | pass | Phase 0 inventory, source map, matrix, command wiring, and stale-term guard exist. |
| `hypervisor-conformance:abi` | pass | Step/Module schemas and current coding-tool projection wrappers exist. |
| `hypervisor-conformance:bridge` | pass | daemon StepModuleRunner boundary, fail-closed Rust workload runner selection, live Rust model_mount provider-execution admission bridge, shared Rust provider invocation bridge for fixture and native-local non-stream execution, retired direct JS local provider non-stream invoke shims, Rust provider-result admission bridge, stream-start provider-result admission guard, native-stream no-downgrade guards, OpenAI-compatible responses no-fallback guard, provider compatibility-translation fail-closed guard, and protocol response facade re-export retirement guard exist without a duplicate JS request-shape append. |
| `hypervisor-conformance:receipts` | pass | Rust StepModule receipt binder exists, model provider execution is admitted before driver calls, fixture and native-local non-stream provider invocation execute in Rust, non-migrated provider results and native stream-start observations are Rust-admitted observations, stream request-shape evidence no longer appends a duplicate JS operation-like record, model invocation and stream-completion receipts carry Rust Agentgres admission, and direct unbound model invocation store appends fail closed. |
| `hypervisor-conformance:ctee` | pass | Rust cTEE Private Workspace module validation exists and untrusted plaintext custody fails closed. |
| `hypervisor-conformance:compositor` | pass | Rust projection records exist, the shadow bridge emits them, and compositor accepted-truth attempts fail closed. |
| `hypervisor-conformance:negative` | pass | All required forbidden-path negative fixtures are implemented at the Rust guard level. |
| `hypervisor-conformance` | pass at current tier surface | Current wired tiers pass; terminal migration is still not claimed until live route families are routed through Rust core and JS facade retirement is complete. |
