# Artifact Context, Generation, And Judge Pass

Date: 2026-03-31
Window: workload-specialized artifact refinement

## Outcome

- `artifact_generation_gate` now runs as an explicit
  `context -> generate -> judge` parent-playbook instead of collapsing
  artifact work into a single build or verify step
- delegated artifact runs now carry typed artifact-generation, artifact-quality,
  and artifact-repair summaries through parent-playbook receipts, the public
  kernel stream, and Spotlight
- the artifact lane now reuses the retained
  `docs/evidence/studio-artifact-surface` parity evidence as the plan-of-record
  backing surface instead of introducing a second artifact strategy

## Key implementation points

- split the artifact playbook into explicit context, generator, and judge steps
  with updated route contracts and catalog coverage:
  `crates/services/src/agentic/desktop/agent_playbooks.rs`
  `crates/services/src/agentic/desktop/worker_templates.rs`
  `crates/services/src/agentic/desktop/service/step/intent_resolver/instruction_contract.rs`
- added typed `ArtifactGenerationSummary`, `ArtifactQualityScorecard`, and
  `ArtifactRepairSummary` structures to parent-playbook state, public receipts,
  and validator/kernel mappings:
  `crates/types/src/app/events.rs`
  `crates/services/src/agentic/desktop/types.rs`
  `crates/ipc/proto/public/v1/public.proto`
  `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- derived artifact summaries from real child outputs, threaded them into
  parent-playbook state, and exposed them in operator-visible projections:
  `crates/services/src/agentic/desktop/service/lifecycle/delegation.rs`
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
  `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
  `apps/autopilot/src-tauri/src/kernel/data/commands/atlas.rs`
  `apps/autopilot/src/types.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`

## Validation

- `cargo test -p ioi-services builtin_agent_playbook_catalog_contains_artifact_generation_gate -- --nocapture`
- `cargo test -p ioi-services seeds_artifact_playbook_for_artifact_task -- --nocapture`
- `cargo test -p ioi-services artifact_generation_gate_surfaces_context_generation_and_quality_receipts -- --nocapture`
- `cargo test -p ioi-services builtin_worker_catalog_contains_workload_specialists -- --nocapture`
- `cargo test -p autopilot default_worker_templates_expose_researcher_contract -- --nocapture`
- `cargo test -p autopilot default_agent_playbooks_expose_artifact_generation_gate_contract -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`
- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
