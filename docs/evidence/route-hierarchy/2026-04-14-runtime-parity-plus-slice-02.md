# Runtime Parity-Plus Slice 02

Date: 2026-04-14
Scope: typed route decisions, projected tool surface, retained benchmark
observations, calmer route receipts

## Shipped

- Added a first-class typed route-decision contract to routing receipts:
  - `route_family`
  - `direct_answer_allowed`
  - `direct_answer_blockers`
  - `currentness_override`
  - `connector_candidate_count`
  - `selected_provider_family`
  - `selected_provider_route_label`
  - `connector_first_preference`
  - `narrow_tool_preference`
  - `file_output_intent`
  - `artifact_output_intent`
  - `inline_visual_intent`
  - `skill_prep_required`
  - `output_intent`
- Added an auditable `effective_tool_surface` with:
  - `projected_tools`
  - `primary_tools`
  - `broad_fallback_tools`
  - `diagnostic_tools`
- Runtime routing receipts now compute and emit this contract across:
  - normal action finalization
  - queue processing
  - refusal receipts
  - resume lifecycle receipts
- Added a shared runtime route-projection module:
  - `crates/services/src/agentic/runtime/service/step/route_projection.rs`
- Public IPC and validator mapping now preserve the typed route decision so the
  contract survives beyond the runtime boundary.
- Spotlight route receipts now expose route-decision truth in:
  - receipt summaries
  - event digests
  - detailed receipt payloads
  - artifact report details
- Spotlight plan summaries now parse route-decision truth directly rather than
  inferring only from older flattened fields.
- `ExecutionRouteCard` now shows a calmer but richer runtime route summary:
  - output intent
  - whether direct answer stayed viable
  - provider preference
  - currentness override
  - skill-prep requirement
  - primary vs broad fallback tool counts
  - projected tool chips
- Capabilities-suite retained evidence now captures:
  - `route_decisions`
  - `tool_normalizations`
- Added direct harness tests for:
  - route-decision observation retention
  - tool-normalization observation retention

## Validation

- `cargo check -p ioi-services --quiet`
- `cargo check -p ioi-validator --quiet`
- `cargo check -p ioi-cli --quiet`
- `cargo check -p autopilot --quiet`
- `cargo test -p ioi-services route_family_uses_resolved_scope_defaults --quiet`
- `cargo test -p ioi-services currentness_override_tracks_research_scope_and_temporal_intents --quiet`
- `cargo test -p ioi-services effective_tool_surface_prefers_selected_provider_and_keeps_fallbacks --quiet`
- `cargo test -p ioi-services browser_postcondition_gate_surfaces_selected_skills_and_prep_summary --quiet`
- `cargo test -p ioi-services artifact_generation_gate_surfaces_context_generation_and_quality_receipts --quiet`
- `cargo test -p ioi-services citation_grounded_brief_surfaces_selected_skills_and_prep_summary --quiet`
- `cargo test -p autopilot parent_playbook_summary_preserves_explicit_route_contract_fields --quiet`
- `cargo check -p ioi-cli --test capabilities_suite_e2e --quiet`
- `cargo test -p ioi-cli --test capabilities_suite_e2e parse_tool_normalization_observation_retains_alias_and_labels --quiet`
- `cargo test -p ioi-cli --test capabilities_suite_e2e route_decision_observation_retains_projected_tool_surface --quiet`
- `npm exec -- tsc -p apps/autopilot/tsconfig.json --noEmit`
- `cd apps/autopilot && npx tsx src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `node --experimental-strip-types apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.test.ts`

## Notes

- `cargo test -p ioi-validator routing_receipt_chain_event_payload_is_complete --quiet`
  is currently blocked by unrelated pre-existing `ioi-validator` lib-test
  failures in consensus and finalize test surfaces. The parity-plus route
  mapping itself still compiles via `cargo check -p ioi-validator --quiet`.
- Full `cargo test -p ioi-cli ...` sweeps are currently affected by unrelated
  pre-existing `reliability_suite_e2e` compile failures. The parity-plus
  benchmark work was isolated by targeting `capabilities_suite_e2e`.

## Sprint outcome

- Route selection is now typed and receipt-backed.
- Projected tool surfaces are auditable per turn instead of remaining implicit.
- Connector-first and narrow-tool preference now have explicit retained truth.
- Benchmark harnesses now retain route and normalization observations for
  future parity scoring.
- Spotlight exposes calmer main-lane route context while preserving inspector
  depth.
