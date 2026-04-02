# Spotlight Inline Execution Card Pass

Date: 2026-03-31
Window: Spotlight execution-surface overhaul

## Outcome

- the primary chat lane now keeps the execution card visible during live work
  and routes raw trace access behind an explicit execution-drawer action instead
  of leading with the standalone worklog pill
- execution summaries now expose typed `currentStage`, `progressSummary`, and
  `pauseSummary` fields so the inline card can explain what the route is doing,
  what just changed, and why it may be paused
- thought and worker summaries now use role labels and step labels from worker
  metadata instead of generic `Agent 1`, `Agent 2` naming
- when a plan summary is present, the live terminal stream no longer takes over
  the primary chat lane by default; summary stays first and raw trace stays
  available second

## Key implementation points

- extended presentation types with role-aware thought summaries and execution
  narrative fields:
  `apps/autopilot/src/types.ts`
- derived stage, progress, pause, and role labels directly from typed activity
  events:
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
  `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- promoted the execution card to the primary live surface and moved trace access
  behind an explicit drawer action:
  `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
  `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx`
  `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`
- surfaced role-labeled thought workers inside the evidence drawer:
  `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubViews.tsx`

## Validation

- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
