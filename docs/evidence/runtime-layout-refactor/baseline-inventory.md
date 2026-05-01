# Runtime Layout Refactor Baseline Inventory

Generated: 2026-05-01

## Public And Runtime Surfaces

| Area | Baseline Evidence | Refactor Decision |
| --- | --- | --- |
| Local daemon API | `scripts/lib/local-runtime-daemon.mjs` owned daemon implementation | Promoted to `packages/runtime-daemon/src/index.mjs`; script launcher remains thin. |
| Agent SDK | `packages/agent-sdk/src/substrate-client.ts` owns daemon-backed SDK transport | Kept SDK as client surface; no GUI/harness imports introduced. |
| Agent IDE runtime adapter | `packages/agent-ide/src/runtime/agent-execution-substrate.ts` looked like execution ownership | Renamed to `runtime-projection-adapter.ts`; IDE remains a workbench projection. |
| Autopilot runtime projection | `apps/autopilot/src-tauri/src/agent_runtime_substrate.rs` looked like substrate ownership | Renamed to `runtime_projection.rs`; Autopilot remains product shell/projection. |
| Runtime contracts | `crates/types/src/app/runtime_contracts.rs` was a broad compatibility module | Added concern-oriented `crates/types/src/app/runtime/*` module family with compatibility re-exports preserved. |
| Step service | `crates/services/src/agentic/runtime/service/decision_loop/` remains large | Added explicit ownership map and migration boundary for decision loop, planning, queue, tool execution, recovery, output, web pipeline, and visual lanes. |
| Built-in tools | Long proof-style include filenames under `runtime/tools/builtins/` | Renamed to tool-family filenames while preserving definitions. |
| Autopilot proofs | Root `src-tauri/src/*_proof.rs` modules mixed validation with product runtime | Moved proof modules under `src-tauri/src/proofs/`; bins call the proof namespace. |
| Roadmap validation names | `run-architectural-improvements-broad-*` were canonical script paths | Added durable `scripts/conformance/runtime-complete-plus.mjs` and `scripts/evidence/runtime-complete-plus.mjs`; roadmap names are thin deprecated wrappers. |

## Dirty Worktree Note

The repo already had unrelated modified/deleted/untracked files before this pass.
This refactor only targeted runtime layout, daemon packaging, proof placement,
contract-family modules, guardrails, and evidence. Existing unrelated application
changes were left intact.
