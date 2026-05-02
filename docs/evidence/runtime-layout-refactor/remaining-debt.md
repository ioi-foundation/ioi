# Runtime Layout Refactor Remaining Debt

Status: No remaining runtime-layout refactor debt.

The previously open physical `step/` split and legacy UI `swarm` vocabulary
migration have been completed.

## Closed Items

| Debt | Closure Evidence |
| --- | --- |
| Physical `service/step/` split | The old `crates/services/src/agentic/runtime/service/step/` tree no longer exists. Runtime service code is physically organized under `decision_loop`, `planning`, `queue`, `tool_execution`, `recovery`, `output`, `web_pipeline`, and `visual_loop` lanes. |
| Legacy active `swarm` UI vocabulary | Active Autopilot UI and artifact presentation fields use work graph terminology. Legacy payload compatibility is isolated in `apps/autopilot/src/types/work-graph-compat.ts`. |
| Retired `ioi-swarm` product package | The stale `ioi-swarm/python` SDK package is removed from the repo, the release workflow doc is gone, and `check:runtime-layout` fails if the retired product package/release surface returns. |

## Compatibility That Remains By Design

- `crates/types/src/app/agentic/market.rs` retains `SwarmManifest` and
  `IntelligenceAsset::Swarm` as legacy marketplace encoding names for persisted
  assets. Runtime code consumes the `WorkGraphManifest` alias.
- `crates/services/src/agentic/runtime/types.rs` retains serde aliases for
  `swarm_id` and `swarm_context` so older JSON checkpoints can hydrate into
  `WorkGraphContext`.
- `apps/autopilot/src/types/work-graph-compat.ts` maps old `swarm*`
  materialization fields and `swarm_tree` to the active work graph fields.
- `apps/autopilot/src-tauri/src/models/chat.rs` and
  `apps/autopilot/src-tauri/src/models/session.rs` retain serde aliases for
  equivalent legacy Tauri payload fields.

These compatibility surfaces decode old persisted data only; they do not own
new runtime behavior or product vocabulary.
