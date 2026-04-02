# Spotlight Turn-Scoped Execution History Pass

Date: 2026-03-31
Window: Spotlight execution-surface overhaul

## Outcome

- turn contexts now derive their own typed plan summaries from the events in
  each turn window, which means execution cards can persist in history instead
  of only appearing for the latest live run
- the execution drawer `Plan` surface now scopes to the selected turn’s events
  instead of falling back to the latest global plan summary
- execution-card opens and turn-default drawer views now align on
  `active_context`, so summary-first history and summary-first drawer behavior
  stay consistent across old and new turns

## Key implementation points

- added per-turn plan-summary derivation inside turn contexts and promoted
  `active_context` to the default view whenever a turn has typed execution
  structure:
  `apps/autopilot/src/windows/SpotlightWindow/hooks/useTurnContexts.ts`
- updated the conversation timeline to render execution cards from turn-scoped
  summaries rather than only from the latest run presentation:
  `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`
- made the execution drawer derive its `Plan` surface from the selected turn’s
  scoped events:
  `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubSidebar.tsx`

## Validation

- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
