# Spotlight UX: history moments and worker cards

Date: 2026-03-31

## What changed

- added typed execution-history moments to the primary chat lane so each turn
  now preserves:
  - branch points
  - approval gates
  - pauses
  - verifier outcomes
- upgraded the `Workers` drawer view from raw note stacks into operator cards
  with explicit objective, current action, and typed verifier or output context
- kept the execution drawer summary-first while leaving raw trace available as
  a secondary surface

## Files

- `apps/autopilot/src/types.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.summaries.ts`
- `apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `apps/autopilot/src/windows/SpotlightWindow/hooks/useTurnContexts.ts`
- `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionMomentList.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubViews.tsx`
- `apps/autopilot/src/windows/SpotlightWindow/styles/Chat.css`
- `apps/autopilot/src/windows/SpotlightWindow/styles/ArtifactPanel.css`

## Validation

- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`

## Outcome

- Spotlight now satisfies the remaining phase-4 requirement from the guide:
  branch and pause history are legible inline, and worker cards expose
  meaningful execution state without forcing operators into raw logs first.
