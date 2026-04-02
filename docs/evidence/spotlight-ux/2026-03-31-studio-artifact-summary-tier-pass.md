# Spotlight Studio Artifact Summary Tier Pass

Date: 2026-03-31
Window: Spotlight execution-surface overhaul

## Outcome

- `StudioArtifactEvidencePanel` now opens with an `At a glance` summary tier so
  artifact trust, judge state, delivery status, and context are visible before
  the longer evidence dump
- the Studio artifact drawer now distinguishes "what happened and why trust it"
  from the raw verification, blueprint, IR, receipts, revision history, and
  workspace activity sections that follow
- the new summary tier reuses retained artifact evidence rather than inventing a
  separate artifact-only surface, which keeps Spotlight aligned with the parity
  plan while still moving the UI toward summary-first behavior

## Key implementation points

- added a compact summary tier for verification, judge, delivery, and context
  using existing manifest, judge, candidate, receipt, and taste-memory data:
  `apps/autopilot/src/windows/SpotlightWindow/components/StudioArtifactEvidencePanel.tsx`
- added dedicated summary-tier styles that keep the glanceable cards visually
  separate from the raw inspector sections:
  `apps/autopilot/src/windows/SpotlightWindow/styles/StudioSurface.css`

## Validation

- `npm run build --workspace=apps/autopilot`
