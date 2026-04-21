# Runtime Boundary

This repo now uses a two-layer boundary for outcome execution:

1. `crates/api/src/runtime_harness.rs`
   Owns product-agnostic runtime semantics:
   - route decisions
   - topology and connector grounding
   - retrieval/source planning
   - operator-run contracts
   - verification semantics
   - artifact planning/materialization contracts

2. `apps/autopilot/.../kernel/studio/*`
   Owns the Studio product shell:
   - session wiring
   - task mutation
   - manifests and receipts
   - event emission
   - Spotlight/Studio presentation surfaces

## Naming Rules

- Generic runtime symbols should avoid `Studio` when they no longer describe a
  Studio-only concern.
- Product-shell contracts and UI models may keep `Studio*` because they are
  genuinely part of the Studio shell.
- During migration, `crates/api/src/studio.rs` remains a compatibility/product-
  shaped facade over the runtime-harness layer.

## Extraction Rules

- Extract semantics first, rename second.
- Keep shell modules thin adapters over shared runtime contracts.
- Prefer lifecycle-focused modules over monolithic orchestration files.
- Keep frontend rendering declarative; move ordering/summary/policy logic into
  viewmodel helpers.

## Reserve Capability

Some `crates/services` support trees intentionally preserve dormant or
experimental capability. Those modules should be explicitly labeled as reserve
support and should not be mistaken for hot-path runtime logic.
