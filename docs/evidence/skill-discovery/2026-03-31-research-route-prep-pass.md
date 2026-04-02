# Research Route Prep Pass

Date: 2026-03-31
Window: registry-backed skill discovery and context prep beyond Studio

## Outcome

- the `citation_grounded_brief` research route now uses registry-backed semantic
  skill recall outside Studio
- delegated research step-spawn receipts now carry explicit
  `selected_skills` and `prep_summary` fields
- Spotlight route summaries render the selected skill chips and prep summary
  from receipts before falling back to heuristics
- when no local memory context is promoted, the route now emits an explicit
  prep summary instead of leaving the operator surface blank

## Key implementation points

- shared the semantic skill discovery substrate between desktop tool injection
  and service-side skill recall:
  `crates/services/src/agentic/desktop/tools/skills.rs`
  `crates/services/src/agentic/desktop/service/skills.rs`
- added research-only prep bundling during delegated child spawn and emitted the
  prep memory receipt on the kernel event stream:
  `crates/services/src/agentic/desktop/service/lifecycle/delegation.rs`
- persisted prep state on parent playbook steps and surfaced it through
  parent-playbook receipts:
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
  `crates/services/src/agentic/desktop/types.rs`
  `crates/types/src/app/events.rs`
  `crates/ipc/proto/public/v1/public.proto`
  `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- rendered the new route prep metadata in Spotlight:
  `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
  `apps/autopilot/src/types.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`
  `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`

## Validation

- `cargo test -p ioi-services citation_grounded_brief_surfaces_selected_skills_and_prep_summary -- --nocapture`
- `cargo test -p ioi-services delegated_research_playbook_flows_through_spawn_and_merge_receipts -- --nocapture`
- `cargo test -p ioi-services evidence_audited_parent_playbook_advances_across_all_steps -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`
- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
