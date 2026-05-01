# Runtime Layout Refactor Checklist

Status: Complete

| Lane | Status | Evidence |
| --- | --- | --- |
| A. Baseline and boundary inventory | Complete | `docs/evidence/runtime-layout-refactor/baseline-inventory.md` |
| B. Runtime module map | Complete | `docs/architecture/operations/runtime-module-map.md`, `docs/architecture/operations/runtime-package-boundaries.md`, `docs/architecture/operations/runtime-vocabulary.md` |
| C. Promote daemon implementation | Complete | `packages/runtime-daemon/src/index.mjs`, `packages/runtime-daemon/package.json`, `scripts/ioi-local-runtime-daemon.mjs` |
| D. Split runtime contracts by family | Complete | `crates/types/src/app/runtime/*.rs`, `crates/types/src/app/mod.rs` |
| E. Physically split overloaded step layer | Complete | `crates/services/src/agentic/runtime/service/{decision_loop,planning,queue,tool_execution,recovery,output,web_pipeline,visual_loop}/`, `docs/evidence/runtime-layout-refactor/step-split-map.md` |
| F. Normalize built-in tool names | Complete | `crates/services/src/agentic/runtime/tools/builtins/*.rs`, `crates/services/src/agentic/runtime/tools/builtins.rs` |
| G. Move proofs out of product runtime namespace | Complete | `apps/autopilot/src-tauri/src/proofs/`, proof bin imports |
| H. Tighten substrate vocabulary | Complete | `runtime-projection-adapter.ts`, `runtime_projection.rs`, vocabulary docs |
| I. Retire swarm as new public/runtime vocabulary | Complete | `apps/autopilot/src/types/work-graph-compat.ts`, `crates/services/src/agentic/runtime/types.rs`, `docs/evidence/runtime-layout-refactor/work-graph-migration-report.md` |
| J. Durable conformance names | Complete | `scripts/conformance/runtime-complete-plus.mjs`, `scripts/evidence/runtime-complete-plus.mjs`, deprecated wrappers |
| K. Runtime layout guardrail | Complete | `npm run check:runtime-layout`, `docs/evidence/runtime-layout-refactor/guardrail-report.json` |

## Compatibility Aliases Retained

- `validate:architectural-improvements-broad` and
  `evidence:architectural-improvements-broad` remain package-script aliases to
  durable complete-plus commands.
- `scripts/run-architectural-improvements-broad-validation.mjs` and
  `scripts/run-architectural-improvements-broad-evidence.mjs` remain thin
  deprecated wrappers for existing operator muscle memory.
- `app::runtime_contracts::*` remains the compatibility re-export surface while
  new Rust code can import from `app::runtime::{tools,cognition,quality,...}`.
- Legacy work graph decoding remains isolated to:
  `apps/autopilot/src/types/work-graph-compat.ts`,
  `apps/autopilot/src-tauri/src/models/chat.rs`,
  `apps/autopilot/src-tauri/src/models/session.rs`,
  `apps/autopilot/src-tauri/src/models/runtime_view_tests.rs`,
  serde aliases on `WorkGraphContext`, and legacy marketplace asset encoding.

No compatibility alias owns new runtime behavior.
