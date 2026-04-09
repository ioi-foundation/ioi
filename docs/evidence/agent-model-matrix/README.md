# Agent Model Matrix

This directory is the retained evidence root for the phase-0 experimental model
matrix described in:

- `docs/plans/ioi-zero-to-hero-agent-systems-guide.md`
- `docs/plans/ioi-zero-to-hero-agent-systems-rolling-plan.md`

Source-of-truth configuration:

- `apps/autopilot/src-tauri/dev/model-matrix-presets.json`

Key files:

- `benchmark-suite.catalog.json`
  Fixed benchmark definitions for the first comparison window. The initial
  window runs retained artifact prompts and a narrow computer-use baseline slice.
- `latest-summary.json`
  Machine-readable comparison summary for the most recent retained matrix run.
  This includes preset availability, scorecards, workload coverage, and the
  keep-default-or-promote decision.
- `latest-summary.md`
  Human-readable digest of the same retained comparison pass.
- `runs/<timestamp>/`
  Per-run retained artifacts, command logs, case outputs, and scorecards.

The scorecard schema is intentionally broader than the first executable slice.
If a workload has not been measured yet, it stays present with
`available: false` and an explicit reason rather than being padded with guessed
values.
