# Spotlight Execution Drawer Truth-Surface Pass

Date: 2026-03-31
Window: Spotlight execution-surface overhaul

## Outcome

- the execution drawer now defaults to a real `Plan` landing view backed by the
  inline execution summary instead of opening directly into worklog-style views
- sidebar labels now speak in operator-facing terms such as `Plan`, `Workers`,
  `Evidence`, `Verification`, and `Raw trace`, with raw trace intentionally
  pushed to the end of the navigation
- the verification drawer section now combines verifier-state summaries from the
  typed plan summary with the existing policy and receipt rows, which makes the
  verifier outcome visible before the raw governance details

## Key implementation points

- threaded `planSummary` into the Spotlight artifact panel and drawer sidebar so
  the drawer can render a first-class plan surface:
  `apps/autopilot/src/windows/SpotlightWindow/components/SpotlightArtifactPanel.tsx`
  `apps/autopilot/src/windows/SpotlightWindow/index.tsx`
- repurposed the dormant `active_context` drawer key into a `Plan` view, updated
  sidebar labels, default ordering, and drawer framing, and renamed the panel
  from `Evidence drawer` to `Execution drawer`:
  `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubSidebar.tsx`
- added a plan-oriented drawer view and a verification-focused detail surface
  that reuses typed verifier summaries before falling back to the raw policy
  rows:
  `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactHubViews.tsx`
- routed inline execution-card opens straight into the plan view so the primary
  chat lane and the drawer now agree on the summary-first landing surface:
  `apps/autopilot/src/windows/SpotlightWindow/components/ConversationTimeline.tsx`

## Validation

- `npx --yes tsx apps/autopilot/src/windows/SpotlightWindow/viewmodels/contentPipeline.test.ts`
- `npm run build --workspace=apps/autopilot`
