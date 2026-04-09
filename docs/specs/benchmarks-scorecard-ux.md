# Benchmarks Scorecard UX Spec

Last updated: 2026-04-05
Owner: benchmarks app / benchmark runner / benchmark app UX
Status: draft

Companion documents:

- `docs/plans/benchmark-combination-matrix-plan.md`
- `docs/plans/meta-harness-master-guide.md`
- `apps/benchmarks/README.md`

## Purpose

Define the target UX for `apps/benchmarks` as a living scorecard-first
benchmark application.

The app should feel closer to a Criterion-style benchmark report than to a raw
operator console:

- benchmark-first
- comparison-first
- baseline-aware
- regression-legible
- quiet and information-dense

The goal is not to imitate Criterion visually line by line.

The goal is to borrow the right interaction stance:

- one-screen understanding before drilldown
- numbers and deltas before prose
- stable comparison surfaces
- clear regressions and blocked comparisons
- retained evidence always reachable

## Product Stance

The benchmarks app should present three truths at once:

1. what is currently winning
2. whether that win is honest and promotable
3. why the operator should trust that answer

That means the app is not primarily:

- a case browser
- a trace explorer
- a pile of retained links

Those remain important, but they should support the scorecard, not replace it.

## Primary Users And Jobs

### Operator

Needs to answer quickly:

- which preset or harness is leading
- whether the lead is promotable
- what is blocked, missing, or invalid
- where to drill down next

### Builder

Needs to answer:

- what changed versus baseline
- which family regressed
- whether a candidate improved the target without cheating

### Meta-layer

Needs a surface that exposes:

- comparable scores
- confidence and coverage
- candidate lineage and acceptance state
- deployment-profile-specific winners

## Core Principles

### 1. Scorecard first, evidence second

The first screen should answer the benchmark question before opening any
artifact links.

### 2. Baseline and delta are first-class

Every major score should be read relative to something:

- current default
- previous accepted baseline
- prior retained run

### 3. Honest incompleteness is better than false certainty

Missing coverage, blocked execution, and invalid comparisons should be visually
louder than a convenient composite score.

### 4. Stable layout beats dashboard novelty

The app should privilege stable rows, columns, and labels so operators can
build memory of where answers live.

### 5. Drilldown should preserve context

Opening a candidate, benchmark, or trace should never make the user lose the
scorecard context they came from.

### 6. One app, multiple reading depths

The same surface should support:

- glance
- compare
- inspect
- diagnose

without forcing every user into the deepest level immediately.

## Information Architecture

The app should move from the current `dashboard` and `triage` split toward four
top-level modes:

- `Scorecard`
- `Candidates`
- `Deployments`
- `Triage`

`Scorecard` should become the default landing mode.

### Scorecard

Primary job:

- answer "what is winning and is it trustworthy?"

### Candidates

Primary job:

- answer "what changed and why was it accepted, rejected, or shadowed?"

### Deployments

Primary job:

- answer "what should be the default for each hardware tier and trust posture?"

### Triage

Primary job:

- inspect case-level failures, traces, and evidence

## Scorecard Home

The scorecard home should read as one coherent report.

### Header band

Show:

- current matrix status
- generated time
- compared presets
- executed presets
- current decision
- whether the shipped default changed

### Decision ribbon

Show a short natural-language answer:

- current leader
- promotability state
- top reason to trust or distrust the decision
- count of missing required families

### Main matrix

The main surface should be a scorecard table.

Rows:

- presets or comparison targets

Columns:

- Base model
- Coding
- Computer use
- Tool/API
- General agent
- Artifacts
- Research
- Latency / resource pressure

Each row should also include:

- preset label
- role
- runtime or judge identity when relevant
- shipped-default badge
- experimental badge

Each cell should show:

- primary score
- delta versus baseline
- confidence or repeat badge
- coverage badge
- invalid or blocked state when comparison is not honest

### Supporting rail

Keep a secondary rail for:

- decision summary
- coverage gaps
- scorecard schema
- retained evidence links

This rail should explain the board, not compete with it.

## Scorecard Cell Semantics

Each scorecard cell should use a consistent visual grammar.

### Primary line

- metric value

### Secondary line

- delta versus baseline

### Tertiary badges

- `required`
- `supporting`
- `blocked`
- `insufficient coverage`
- `low confidence`
- `not comparable`

### Color rules

- green only for honest improving or passing states
- amber for caution, partial coverage, or shadow-worthy results
- red for blocking regressions or invalid promotion paths
- neutral for unavailable or non-comparable states

Color should never be the only channel; text badges must carry meaning too.

## Criterion-Like Interaction Patterns

The app should adopt these Criterion-like reading patterns:

- stable rows and columns across refreshes
- clear baseline-versus-candidate framing
- visible regression direction, not just raw numbers
- quiet chrome around the numbers
- drilldown available from each metric without changing the meaning of the
  summary board

It should not adopt:

- chart junk as the primary surface
- decorative heatmaps without explicit semantics
- one giant scalar leaderboard that hides family regressions

## Candidates View

The candidates view should be ledger-first.

Each candidate row or card should show:

- candidate id
- parent candidate
- target family
- mutation intent
- decision state
- target metric delta
- required-family regressions
- conformance result
- deployment profile

Selecting a candidate should open:

- changed contracts or files
- proxy, validation, challenge, and holdout results
- cross-family regressions
- role-model assignment diff
- accept, reject, or revert trail

## Deployments View

The deployments view should answer default selection by environment.

Each deployment profile should show:

- current default
- challenger
- confidence level
- cloud posture
- role-model composition
- whether the answer is profile-specific or shared across profiles

The user should be able to compare:

- local versus blind cloud
- constrained local versus workstation
- text-only versus multimodal-capable compositions

## Triage View

The triage view remains important, but it should be clearly downstream of the
scorecard.

It should preserve the current strengths:

- suite filters
- case list
- live run visibility
- trace replay and case-level diagnostics

But the user should arrive there from a scorecard context such as:

- "why is this cell red?"
- "which case is driving this regression?"
- "show the evidence behind this blocked comparison"

## Visual System

### Tone

- restrained
- benchmark-lab serious
- high signal
- low ornament

### Typography

- numbers should be more visually prominent than prose
- labels should be compact and stable
- long summaries should not dominate the main scorecard

### Layout

- table or grid first
- sticky row headers or sticky family headers when helpful
- consistent cell sizes where possible
- compact badges over large narrative panels

### Motion

- subtle live-refresh transitions only
- avoid dashboard-style animation noise

## Data And Component Implications

The UX implies a component model more explicit than the current mixed dashboard:

- `ScorecardBoard`
- `ScorecardRow`
- `ScorecardCell`
- `DecisionRibbon`
- `CandidateLedgerView`
- `DeploymentBoard`
- `EvidenceDrilldown`

The data model should support:

- baseline id per comparison context
- delta values per family
- confidence and coverage summaries per family
- promotability state
- blocked or invalid reasons
- deployment-profile grouping

## Redesign Implications For The Current App

The current app is already useful, but it is still organized like an operator
dashboard with embedded benchmark panels.

### 1. The primary landing mode should change

Current state:

- `dashboard` and `triage` are the only top-level tabs

Implication:

- `dashboard` should become `scorecard`
- `triage` should remain, but no longer define the whole product posture

### 2. The model matrix should stop being just one panel in the dashboard

Current state:

- the agent model matrix lives mid-page inside the broader dashboard

Implication:

- the scorecard should become the primary page structure
- evidence and supporting panels should become subordinate rails or drawers

### 3. Suite-level case KPIs should move down a level

Current state:

- the app opens with suite cards and case-oriented KPIs

Implication:

- suite and case health should live inside `Triage`
- top-level KPIs should speak in matrix terms such as leader, promotability,
  coverage, and blocked comparisons

### 4. Current metric tiles should become true scorecard cells

Current state:

- each preset row contains a small cluster of score tiles

Implication:

- those tiles should become column-consistent cells in a board layout
- deltas, confidence, and invalid states should be attached directly to the
  cell

### 5. Evidence should remain present but visually demoted

Current state:

- evidence links and schema explanation are side blocks beside the matrix

Implication:

- keep them, but frame them as support for the scorecard decision rather than
  peer content

### 6. Artifact and matrix surfaces should converge visually

Current state:

- the matrix, artifact parity ladder, arena, and gate views share some styles
  but read like separate product surfaces

Implication:

- they should share one scorecard language for rows, status, deltas, and
  promotability

### 7. Live updates should strengthen the "living scorecard" feel

Current state:

- the app already polls and merges live data

Implication:

- live refresh should update scorecard cells, leader state, and blocked badges
  without turning the main board into a noisy live console

## Rollout Guidance

### Phase 1

- promote the matrix to the primary landing surface
- preserve existing data sources
- reuse existing row and stat components where possible

### Phase 2

- add candidate and deployment views
- add stronger baseline and delta semantics
- demote evidence into rails and drawers

### Phase 3

- add chart-ready exports and trend sparklines where they add value
- keep the scorecard board as the dominant reading surface

## Success Criteria

The UX is successful when:

- an operator can identify the current leader in under ten seconds
- an operator can tell whether the lead is promotable without opening raw
  evidence
- a regression is visually obvious before the user reads paragraph text
- a missing-coverage or non-comparable state is harder to miss than a vanity
  aggregate score
- triage remains powerful without being the first thing every user has to parse
