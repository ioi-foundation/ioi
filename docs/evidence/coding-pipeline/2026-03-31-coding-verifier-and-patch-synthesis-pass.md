# Coding Verifier And Patch Synthesis Pass

Date: 2026-03-31
Window: workload-specialized coding refinement

## Outcome

- `evidence_audited_patch` now runs as an explicit
  `context -> implement -> verify -> synthesize` parent-playbook instead of a
  collapsed research-and-audit flow
- delegated coding runs now carry typed coding-verification and patch-synthesis
  summaries through parent-playbook receipts and the public kernel stream
- Spotlight route summaries now separate repo context, coding verification, and
  patch synthesis so operators can see whether a patch was actually checked
  before it is presented as complete

## Key implementation points

- split the coding playbook into bounded `repo_context_brief`,
  `patch_build_verify`, `targeted_test_audit`, and
  `patch_synthesis_handoff` workflows with dedicated worker templates:
  `crates/services/src/agentic/desktop/worker_templates.rs`
  `crates/services/src/agentic/desktop/agent_playbooks.rs`
  `crates/services/src/agentic/desktop/service/step/intent_resolver/instruction_contract.rs`
- generalized delegated prep so coding context workers can receive
  registry-backed skills and bounded repo-memory summaries instead of borrowing
  the research path:
  `crates/services/src/agentic/desktop/service/lifecycle/delegation.rs`
- added typed `CodingVerificationScorecard` and `PatchSynthesisSummary`
  structures to parent-playbook state, public receipts, and validator/kernel
  mappings:
  `crates/types/src/app/events.rs`
  `crates/services/src/agentic/desktop/types.rs`
  `crates/ipc/proto/public/v1/public.proto`
  `crates/validator/src/standard/orchestration/grpc_public/events_handlers/kernel_mapping.rs`
- preserved step-to-step dependency context by threading a compact parent
  playbook context block from each completed step into the next worker goal and
  deriving typed coding receipts from the real verifier/synth outputs:
  `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
- projected the new coding receipts into Spotlight and rendered them as
  dedicated operator-visible sections:
  `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
  `apps/autopilot/src/types.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`

## Validation

- `cargo test -p ioi-services evidence_audited_parent_playbook_advances_across_all_steps -- --nocapture`
- `cargo test -p ioi-services context_worker_playbook_merge_preserves_playbook_identity -- --nocapture`
- `cargo test -p ioi-services builtin_worker_catalog_contains_workload_specialists -- --nocapture`
- `cargo test -p ioi-services builtin_agent_playbook_catalog_contains_evidence_audited_patch -- --nocapture`
- `cargo test -p autopilot default_agent_playbooks_expose_evidence_audited_patch_contract -- --nocapture`
- `cargo test -p autopilot default_worker_templates_expose_researcher_contract -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`
- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
