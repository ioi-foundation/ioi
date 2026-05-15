# Computer Use External Eval Ingestion Master Guide

Owner: agent runtime / benchmark harness / Autopilot / SDK

Status: future-platform leg, ready for implementation after provider selection

Created: 2026-05-15

## Executive Verdict

The local computer-use harness can emit deterministic trajectories, scorecards,
and improvement plans. The remaining eval deferral is ingestion of external
task suites such as OSWorld, ScreenSpot, WorkArena, WebArena-style browser
tasks, and provider-specific benchmark traces.

This guide turns that deferral into a concrete ingestion leg. IOI should not
copy external benchmark runtimes. It should import task definitions and results
into IOI's canonical trajectory, receipt, and scorecard model.

## Doctrine

- External eval suites are inputs, not runtime truth.
- Eval adapters compile tasks into IOI workflow manifests and provider leases.
- Scores must be derived from IOI observations, actions, verification receipts,
  trajectories, and failure taxonomy.
- Raw benchmark artifacts must follow retention and redaction policy.
- No hidden benchmark shortcuts or task-specific bypasses.

## Target Inputs

| Suite family | Ingestion target |
| --- | --- |
| OSWorld-style desktop tasks | Isolated computer provider task manifest plus visual/AX observation policy. |
| ScreenSpot-style grounding tasks | Observation bundle plus target-index/affordance grounding cases. |
| WorkArena/WebArena-style browser tasks | Native browser or isolated browser task manifest with DOM/AX/selector evidence. |
| Provider-native traces | Imported as non-authoritative reference trajectories. |
| Internal retained tasks | Exported and re-imported to prove deterministic replay compatibility. |

## Canonical Output Shape

Each imported case should become:

- `ComputerUseBenchmarkCase`
- `WorkflowManifest`
- `ProviderRequirement`
- `ObservationRetentionMode`
- `ExpectedOutcomeContract`
- `EvaluationRubric`
- `TrajectoryBundle`
- `FailureTaxonomyRecord`
- `ScorecardRow`
- `PromotionGateReceipt`

## Ingestion Pipeline

```text
discover_suite
-> parse_case
-> normalize_goal
-> map_environment
-> map_observation_policy
-> map_success_criteria
-> compile_workflow_manifest
-> execute_or_import_trajectory
-> evaluate_receipts
-> write_scorecard
-> emit_improvement_plan
```

## Required Failure Taxonomy

Eval failures must classify at least:

- environment unavailable;
- provider boot failure;
- observation missing;
- target grounding failure;
- affordance inference failure;
- policy/approval block;
- action execution failure;
- verification failure;
- cleanup failure;
- task ambiguity;
- external suite incompatibility.

## Autopilot Workbench

Autopilot should show:

- imported suite and case id;
- mapped provider lane;
- task manifest and authority posture;
- observation and target-index evidence;
- trajectory timeline;
- scorecard row;
- failure classification;
- promotion gate status;
- links to retained redacted artifacts.

## Validation Plan

Required tests:

- fixture OSWorld-like case imports to IOI benchmark case;
- fixture ScreenSpot-like grounding case imports to target-index eval;
- fixture WorkArena-like browser case imports to browser workflow manifest;
- imported cases refuse to run without required provider capabilities;
- raw artifacts are excluded unless local-private retention is explicit;
- deterministic exported IOI case re-imports without semantic drift;
- scorecard aggregation separates pass, fail-closed, failed, blocked, and
  external-unavailable cases.

## Definition Of Done

This leg is complete when:

- at least one fixture adapter exists for each targeted suite family;
- external cases compile to deterministic IOI manifests;
- execution uses IOI isolated computer providers or native browser lanes;
- imported and generated trajectories share one schema;
- scorecards are comparable across internal and external cases;
- Autopilot can inspect imported cases, trajectories, and promotion blockers;
- provider or suite unavailability is a narrow explicit blocker, not a skipped
  success.
