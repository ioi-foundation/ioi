# Research Citation Verifier Scorecard Pass

Date: 2026-03-31
Window: workload-specialized research refinement

## Outcome

- `citation_grounded_brief` now routes its verifier step through a dedicated
  `citation_audit` workflow instead of the generalized postcondition audit
- parent-playbook receipts now carry a typed research verification scorecard
  with verdict, source coverage, domain independence, freshness, and
  quote-grounding fields
- Spotlight route summaries render the research verifier state separately from
  prep context and final synthesis so operators can see whether the brief was
  actually grounded before it was accepted

## Key implementation points

- bound the research playbook to a dedicated verifier workflow and completion
  contract:
  `crates/services/src/agentic/desktop/worker_templates.rs`
  `crates/services/src/agentic/desktop/agent_playbooks.rs`
  `crates/services/src/agentic/desktop/service/step/intent_resolver/instruction_contract.rs`
- added a typed `ResearchVerificationScorecard` to parent-playbook state and
  public receipts:
  `crates/services/src/agentic/desktop/types.rs`
  `crates/types/src/app/events.rs`
  `crates/ipc/proto/public/v1/public.proto`
  `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- derived the scorecard from the verifier output plus the stored research
  worker result so source and domain counts come from the real cited brief
  instead of a collapsed summary:
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
- projected the scorecard through the kernel event stream into Spotlight:
  `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
  `apps/autopilot/src/types.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`

## Validation

- `cargo test -p ioi-services citation_grounded_brief_surfaces_research_verifier_scorecard -- --nocapture`
- `cargo test -p ioi-services builtin_worker_catalog_contains_workload_specialists -- --nocapture`
- `cargo test -p ioi-services builtin_agent_playbook_catalog_contains_citation_grounded_brief -- --nocapture`
- `cargo test -p ioi-services citation_grounded_brief_surfaces_selected_skills_and_prep_summary -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`
- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
