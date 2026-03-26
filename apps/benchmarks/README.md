# Benchmarks App

`apps/benchmarks` is the living React operator surface for computer-use
benchmark work in this repo.

It mirrors:

- the rolling local store at
  `apps/benchmarks/src/generated/benchmark-store.json`
- latest linked run artifacts for the retained window

The app exists to make live suite status, latest retained slices, and
case-level diagnostics readable for both human operators and autonomous agents.

## Commands

- `npm run dev:benchmarks`
- `npm run build:benchmarks`
- `npm run typecheck:benchmarks`

## Data flow

- live `computer_use_suite` agent runs now publish a rolling local store and
  per-case teardown summaries automatically.
- live runs now also synthesize per-case `trace_bundle.json` and
  `trace_analysis.json` artifacts for replay-oriented observability work.
- `apps/benchmarks/scripts/generate-benchmark-data.mjs` reads the retained
  store and case artifacts.
- The generated payload is written to
  `apps/benchmarks/src/generated/benchmark-data.json`.
- The React app renders that payload as the living benchmark surface.
