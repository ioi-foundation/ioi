# Explicit Hierarchy Pass

Date: 2026-03-31

## Summary

- promoted workload hierarchy from implicit heuristics to an explicit route
  contract for coding, research, computer use, and artifact parent playbooks
- threaded `route_family`, `topology`, and `verifier_state` through
  parent-playbook receipts and the Autopilot receipt stream
- updated Spotlight summary generation to prefer explicit route metadata before
  heuristic fallback and added a dedicated computer-use route fixture

## Key files

- `crates/services/src/agentic/desktop/agent_playbooks.rs`
- `crates/services/src/agentic/desktop/service/lifecycle/worker_results.rs`
- `crates/types/src/app/events.rs`
- `crates/ipc/proto/public/v1/public.proto`
- `apps/autopilot/src-tauri/src/kernel/events/stream/workload_receipt.rs`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`

## Validation

- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `cargo test -p ioi-services playbook_route_contracts_cover_primary_workload_families -- --nocapture`
- `cargo test -p ioi-services evidence_audited_parent_playbook_advances_across_all_steps -- --nocapture`
- `cargo test -p autopilot default_agent_playbooks_expose_evidence_audited_patch_contract -- --nocapture`
- `cargo test -p autopilot parent_playbook_projection_tracks_live_step_status_and_receipts -- --nocapture`

## Outcome

- hierarchy window exit criteria satisfied without changing the shipped default
  model preset
- route topology and verifier status now arrive in operator-visible receipts
  instead of being reconstructed only from raw worklog fragments
