# Work Graph Vocabulary Migration Report

Status: Complete.

Active runtime and product vocabulary now uses work graph/adaptive work graph
terms instead of `swarm`.

## Migrated Surfaces

| Surface | New vocabulary |
| --- | --- |
| Autopilot execution contracts | `WorkGraphPlan`, `WorkGraphExecutionSummary`, `WorkGraphWorkerReceipt`, `workGraphPlan`, `workGraphExecution`, `workerReceipts`, `changeReceipts`, `mergeReceipts`, `verificationReceipts` |
| Autopilot session model | `WorkGraphAgent`, `work_graph_tree` |
| Autopilot visualization | `WorkGraphViz`, `Work graph orchestration` |
| Runtime agent state | `WorkGraphContext`, `work_graph_context`, `work_graph_id` |
| Runtime hydration | `WORK_GRAPH:<hash>` primary goal prefix and `fetch_work_graph_manifest` |
| Chat strategy enum | `MicroWorkGraph` and `AdaptiveWorkGraph` |

## Legacy Decoding

The migration preserves old data through explicit compatibility only:

- `apps/autopilot/src/types/work-graph-compat.ts` maps old `swarm*`
  materialization fields and `swarm_tree`.
- `apps/autopilot/src-tauri/src/models/chat.rs` and
  `apps/autopilot/src-tauri/src/models/session.rs` retain serde aliases for old
  Tauri payload fields while serializing active work graph names.
- `apps/autopilot/src-tauri/src/models/runtime_view_tests.rs` proves old
  `swarm_tree` payloads still decode into `work_graph_tree`.
- `WorkGraphContext` has serde aliases for old `swarm_id` and
  `swarm_context` JSON fields.
- Marketplace asset encoding keeps `SwarmManifest` and
  `IntelligenceAsset::Swarm`; runtime code uses the `WorkGraphManifest` alias.
- `WORK_GRAPH:<hash>` is the primary runtime prefix; `SWARM:<hash>` remains a
  legacy parse alias in the start handler.

Guardrail:

- `npm run check:runtime-layout` fails if active runtime/UI/API code
  reintroduces `swarm` vocabulary outside explicit compatibility files.
