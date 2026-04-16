# Domain Topology Gap Closure

Date: 2026-04-16
Owner: Studio / Spotlight / runtime
Status: implemented and validated

## Summary

The domain-topology gap back-engineering pass is now implemented end to end.

The runtime no longer treats the follow-up corpus as a prompt-only design note.
It now retains typed domain topology and orchestration state across planning,
kernel route contracts, and Spotlight inspector surfaces.

## What shipped

### Shared topology and orchestration projection

- Added a shared topology derivation path in
  `crates/api/src/studio/domain_topology.rs`
- Planner payloads now retain:
  - `lane_frame`
  - `request_frame`
  - `source_selection`
  - `retained_lane_state`
  - `lane_transitions`
  - `orchestration_state`
- The new projection is threaded through:
  - `crates/api/src/studio/planning/routing.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session/connectors.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session/non_artifact.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session/route_contract.rs`

### Domain-first route semantics

- Studio now keeps the primary lane domain-first instead of collapsing
  connector-backed communication requests into a generic integrations family.
- Connector-backed communication now reads as:
  - primary lane: `communication`
  - selected source: `connector`
  - retained secondary transition: `communication -> integrations`
- Planned secondary lane transitions are now explicit receipts instead of
  implicit behavior.

### Shared request shaping

- `StudioIntentContext` now supplies shared extraction helpers for:
  - weather
  - sports
  - places
  - recipe
  - message compose
  - user-input / prioritization
- `prepare.rs` now reuses the shared extraction path instead of carrying
  separate lexical drift for key specialized domains.

### Spotlight inspector support

- `apps/autopilot/src/types.ts` now exposes typed plan-summary models for:
  - route families beyond the original four
  - lane frames
  - normalized request frames
  - source selection
  - retained lane state
  - lane transitions
  - orchestration state
- `contentPipeline.routeContracts.ts` now parses the new route-contract
  payloads into plan summaries.
- `ExecutionRouteCard.tsx` now surfaces:
  - primary lane and goal
  - request-frame summaries
  - source selection
  - secondary lanes
  - retained lane state
  - lane transitions
  - objective/task/checkpoint summaries
- Route-family labels and operator copy were expanded across:
  - `runtimeStatusCopy.ts`
  - `contentPipeline.summaries.ts`
  - `SpotlightOperatorStrip.tsx`
  - `SpotlightOrchestrationBoard.tsx`

### Cleanup

- Removed dead helper seams made obsolete by the refactor in:
  - `apps/autopilot/src-tauri/src/kernel/studio/content_session/route_contract.rs`
  - `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`

## Validation

Passed:

- `cargo check -p ioi-api --quiet`
- `cargo check -p autopilot --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api weather_route_derives_lane_frame_request_frame_and_source_selection --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api communication_projection_infers_message_compose_lane_and_missing_slots --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p autopilot route_contract_payload_maps_weather_widget_to_research_surface --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p autopilot route_contract_payload_preserves_connector_source_selection_and_lane_transition --quiet`
- `npm exec -- tsc -p apps/autopilot/tsconfig.json --noEmit`
- `cd apps/autopilot && npx tsx src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`

## Result

The implementation bridge in
`docs/plans/claude-harness-domain-topology-gap-back-engineering.md` is now
substantively closed:

- lane-first topology is explicit
- high-value specialized request frames are typed
- source ranking is retained
- lane transitions are receipt-backed
- retained lane state is modeled
- orchestration state is visible in the inspector

The remaining work is no longer parity gap closure. It is a separate product
decision about how far to push long-form execution policy and adaptive work
graphs in the next sprint.
