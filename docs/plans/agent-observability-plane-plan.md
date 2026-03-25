# Agent Observability Plane Plan

## Why this exists

The current computer-use debugging loop is artifact-heavy but replay-poor. We
can recover the truth after a run by reading `diagnostic_summary.json`,
`benchmark_summary.json`, `inference_trace.json`, `inference_calls.json`,
`bridge_state.json`, and `kernel_events.json`, but we do not yet have one
canonical timeline that an operator or agent can scrub, diff, and inspect.

This document defines the implementation path from today's benchmark artifacts
to a shared observability plane used by:

- `apps/benchmarks` as the benchmark triage and capability-analysis surface
- `apps/autopilot` as the agent IDE timeline / trace / receipts surface

The core doctrine is:

- build one canonical local trace substrate
- derive benchmark capability metrics from that substrate
- render the same substrate differently in `benchmarks` and `autopilot`

## Product shape

The target interaction model is closer to a video editing or VFX suite than a
traditional log viewer:

- the run is replayable on a timeline
- lanes separate inference, tool execution, browser state, bridge state,
  receipts, and failures
- expanding a clip reveals prompt, arguments, outputs, receipts, and artifacts
- capability metrics link back to the exact trace spans that justified them
- run-to-run diff shows the first meaningful divergence

The visual metaphor is important, but the real product is the trace contract and
the local evidence graph underneath it.

## Principles

- One canonical trace bundle per run/case, many views over it.
- Keep benchmark store light; keep heavy traces in bounded local artifacts.
- Prefer span-based structured evidence over free-form logs.
- Every capability metric must retain links back to the trace spans and source
  artifacts that justified it.
- MVP starts from teardown synthesis over existing artifacts; end state moves to
  native runtime span emission.

## Shared data model

### Trace bundle

Every live case should emit a `trace_bundle.json` with:

- `trace_id`, `run_id`, `case_id`, `env_id`, `suite`
- `generated_at_ms`
- `summary`
- `findings`
- `source_artifacts`
- `spans[]`
- `bookmarks[]`

### Span contract

Each span should include:

- `id`
- `lane`
- `parent_span_id`
- `step_index`
- `capability_tags[]`
- `ts_start_ms`
- `ts_end_ms`
- `duration_ms`
- `status`
- `summary`
- `attributes`
- `artifact_refs[]`

### Analysis contract

Each live case should also emit `trace_analysis.json` with:

- `trace_id`, `run_id`, `case_id`
- `metrics[]`
- `findings[]`
- `bookmarks[]`

Each metric should include:

- `metric_id`
- `label`
- `status`
- `summary`
- `supporting_span_ids[]`
- `supporting_artifacts[]`

## Capability taxonomy

The initial shared tags and metric families should be:

- `overall_case_outcome`
- `observation_surface`
- `verification_signal`
- `execution_runtime`
- `bridge_sync_observability`
- `planning_contract`
- `startup_latency`
- `geometry_fidelity`

These should be treated as additive. A single span may support multiple
capability metrics.

## Storage and retention

### Benchmark store

`apps/benchmarks/src/generated/benchmark-store.json` should store:

- bounded retained runs
- per-case summary refs
- per-case trace refs

It should not inline full trace payloads.

### Local retention policy

Keep, per case:

- latest trace
- latest failing trace
- latest passing trace

Retention should be bounded automatically. Old bundles may be pruned once newer
equivalents exist.

## MVP plan

### Phase 1: Teardown trace synthesis

Source of truth:

- `diagnostic_summary.json`
- `benchmark_summary.json`
- `inference_calls.json`
- `inference_trace.json`
- `bridge_state.json`
- `kernel_events.json`

Implementation:

- synthesize `trace_bundle.json` at harness teardown
- synthesize `trace_analysis.json` from current findings and phase evidence
- publish trace refs into the benchmark store

Success criteria:

- every live case has a canonical trace bundle and analysis file
- benchmark store retains refs to those files

### Phase 2: Benchmarks integration

Implementation:

- extend `generate-benchmark-data.mjs` to read trace analysis refs
- surface trace bundle and trace analysis links in `apps/benchmarks`
- render trace-derived capability metrics in case detail

Success criteria:

- clicking a red case in `benchmarks` exposes the trace artifacts immediately
- capability metrics are visible and backed by supporting span ids

### Phase 3: Benchmarks replay viewer

Implementation:

- add scrubber/playhead
- add lane view for spans
- add selection inspector for a chosen span
- keep current step list as compact fallback

Success criteria:

- operators can scrub a run instead of reading multiple artifact files by hand

### Phase 4: Autopilot read-only trace surface

Implementation:

- add Tauri commands to enumerate local trace bundles
- replace placeholder trace/receipts views in `autopilot` with real trace data
- support opening a run by `run_id` or `case_id`

Success criteria:

- `autopilot` can inspect the same trace bundles as `benchmarks`

## Full end-state plan

### Native runtime span emission

Replace teardown-only synthesis with direct span emission from:

- inference runtime
- service execution phases
- browser driver operations
- bridge sync and event delivery
- judge evaluation
- receipts and governed workload execution

### Live trace streaming

Add a local stream so `autopilot` can watch a run live:

- moving playhead
- incremental span insertion
- live failure markers
- artifact updates while the run is still executing

### Run diffing

Support:

- fail vs fail
- fail vs pass
- retained red vs current rerun

The primary UX should answer:

- where did the runs diverge first?
- which capability metric changed?
- which span evidence changed?

### Indexed local search

Once file scanning becomes too slow, add a local trace index, likely SQLite, for:

- spans by capability tag
- failures by tool / phase / timeout class
- case / run lookup
- benchmark metric backreferences

### Media-rich replay

After the trace substrate is stable:

- add snapshot filmstrip
- add synchronized final / intermediate screenshots
- add DOM / accessibility overlay diff views
- add bridge-state overlays

This should come after the core evidence model, not before it.

## UI responsibilities

### `apps/benchmarks`

Role:

- benchmark triage
- retained-red review
- capability metric summary
- quick access to trace evidence

Responsibilities:

- show current benchmark status
- show trace-derived metrics
- deep-link into supporting spans
- support run diff and benchmark-case comparison

### `apps/autopilot`

Role:

- operator IDE
- live run observability
- deep trace inspection
- cross-run investigation

Responsibilities:

- real-time and local replay
- lane-based timeline
- receipts and policy evidence view
- artifact inspector
- trace search

## Rollout sequence

1. Add teardown trace synthesis and trace refs.
2. Surface trace refs and metrics in `benchmarks`.
3. Add replay viewer in `benchmarks`.
4. Add trace loading in `autopilot`.
5. Add live streaming and native runtime spans.
6. Add diff mode and indexed search.

## Acceptance criteria

The observability plane is doing its job when:

- a red benchmark card opens directly to the culpable spans
- a capability metric can show the exact evidence that made it red
- `autopilot` and `benchmarks` agree on the same local trace truth
- we can compare last fail vs last pass without manually stitching artifacts
- repeated blind reruns stop being the default debugging loop

## Immediate implementation notes

The first substrate is intentionally conservative:

- synthesize trace bundle and trace analysis from existing teardown truth
- keep local state bounded
- do not block on perfect runtime instrumentation
- treat the current trace contract as versioned and forward-migratable

That gives us an honest MVP now while leaving room to grow into the full
observability plane.
