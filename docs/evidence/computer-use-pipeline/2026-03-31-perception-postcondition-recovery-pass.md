# Computer-Use Perception, Postcondition, And Recovery Pass

Date: 2026-03-31
Window: workload-specialized computer-use refinement

## Outcome

- `browser_postcondition_gate` now runs as an explicit
  `perceive -> execute -> verify` parent-playbook instead of collapsing
  perception, execution, and verification into one browser worker summary
- delegated browser runs now carry typed perception, postcondition-verification,
  recovery, and approval-state summaries through parent-playbook receipts and
  the public kernel stream
- Spotlight route summaries now separate what the system saw, what it did, what
  the verifier concluded, and whether approval or recovery was required before
  the route is shown as complete

## Key implementation points

- added a bounded `perception_worker` and the
  `ui_state_brief` / `browser_postcondition_audit` workflows so the browser
  playbook has explicit perception and verifier stages:
  `crates/services/src/agentic/desktop/worker_templates.rs`
  `crates/services/src/agentic/desktop/agent_playbooks.rs`
  `crates/services/src/agentic/desktop/service/step/intent_resolver/instruction_contract.rs`
- introduced typed `ComputerUsePerceptionSummary`,
  `ComputerUseVerificationScorecard`, and `ComputerUseRecoverySummary`
  structures in parent-playbook state, public receipts, and validator/kernel
  mappings:
  `crates/types/src/app/events.rs`
  `crates/services/src/agentic/desktop/types.rs`
  `crates/ipc/proto/public/v1/public.proto`
  `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- derived computer-use receipts from real child outputs, threaded them into
  parent-playbook state, and preserved completed ancestor context so the
  verifier sees perception plus execution state rather than only the direct
  child summary:
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
- projected the new computer-use receipts into Spotlight and rendered them as
  dedicated `UI perception`, `Computer-use verification`, and `Recovery`
  sections with explicit approval states:
  `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
  `apps/autopilot/src-tauri/src/kernel/data/commands/atlas.rs`
  `apps/autopilot/src/types.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`

## Validation

- `cargo test -p ioi-services builtin_agent_playbook_catalog_contains_browser_postcondition_gate -- --nocapture`
- `cargo test -p ioi-services builtin_worker_catalog_contains_workload_specialists -- --nocapture`
- `cargo test -p ioi-services seeds_browser_playbook_for_browser_task -- --nocapture`
- `cargo test -p ioi-services browser_postcondition_gate_surfaces_perception_and_recovery_receipts -- --nocapture`
- `cargo test -p autopilot default_worker_templates_expose_researcher_contract -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`
- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
