# Runtime Parity-Plus Slice 01

Date: 2026-04-14
Scope: route-contract projection, conditional guidance truth, tool-boundary
observability

## Shipped

- Parent-playbook workload receipts now preserve explicit route-contract fields
  in streamed Spotlight digests and details:
  - `planner_authority`
  - `verifier_role`
  - `verifier_outcome`
- Capabilities-suite parent-playbook observations now retain the same route
  fields so benchmark evidence can compare runtime and UI truth.
- Studio skill discovery now carries an explicit `guidance_status` with the
  states:
  - `pending`
  - `not_needed`
  - `attached`
  - `unavailable`
- Studio skill-discovery completion messaging now distinguishes:
  - guidance not needed
  - guidance attached
  - guidance unavailable
- Spotlight artifact-thinking labels now respect runtime-provided
  skill-discovery titles, so the main lane can say `Guidance unavailable` or
  `Guidance not needed` instead of always showing `Check for guidance`.
- Tool normalization now emits explicit observation data at the runtime
  boundary:
  - raw tool name
  - normalized tool name
  - whether normalization changed the call
  - a list of normalization and coercion labels
- Tool-normalization observations are now attached to:
  - routing `verification_checks`
  - the persisted `action_payload`

## Validation

- `cargo test -p autopilot parent_playbook_summary_preserves_explicit_route_contract_fields --quiet`
- `cargo test -p autopilot pipeline_steps_keep_skill_discovery_distinct_from_brief_preparation --quiet`
- `cargo test -p autopilot pipeline_steps_for_ready_markdown_artifact_are_complete --quiet`
- `cargo test -p ioi-services test_normalize_with_observation --quiet`
- `cargo check -p ioi-cli --quiet`
- `npm exec -- tsc -p apps/autopilot/tsconfig.json --noEmit`
- `node --experimental-strip-types apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.test.ts`

## Notes

- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
  was covered by TypeScript compilation, but not executed directly via `node`
  because the file still relies on extensionless ESM imports that Node does not
  resolve in this mode.

## Remaining sprint work

- introduce the first-class typed route-decision contract described in the
  sprint plan
- expose an auditable effective per-turn tool surface, not just discovered tool
  supersets
- extend the calmer implicit-by-default storytelling pass beyond guidance labels
  into the broader active-run chrome
