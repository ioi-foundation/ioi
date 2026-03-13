# Browser / Computer-Use Discovery Plan

This document replaces the retired `miniwob-computer-use-suite` expansion plan.
The file path stays stable so existing references do not break, but the strategy is
now different:

- primary discovery lane: live inference on browser-first external benchmarks
- secondary reproduction lane: deterministic local reproductions for reusable gaps
- regression lane: MiniWoB plus local workflow fixtures

The prior plan succeeded at regression hardening, but it drifted from the product
discovery north star. The correction is to stop treating deterministic local
benchmark expansion as the main frontier and instead use it only after live runs
surface real product gaps.

## Status

Current phase:

- Active frontier: prove and use real live inference on the repo's existing browser
  / computer-use stack, then push that stack against BrowserGym-style browser-first
  benchmarks.
- Retired as primary frontier: the deterministic `computer_use_suite` MiniWoB and
  local workflow ladder. Those baselines remain valuable, but they are no longer
  the main product-gap discovery source.
- Target north star:
  - first: live inference + browser-first benchmark, preferably WorkArena or
    WebArenaVerified through a BrowserGym-style integration
  - next: live inference + cross-app computer-use benchmark, preferably OSWorld or
    OSWorld-Verified
  - ongoing: keep deterministic MiniWoB and local workflow coverage as CI and
    regression protection for reusable primitives, observations, verification, and
    recovery behaviors

Current assessment:

- The repo already has deterministic browser/computer-use harness coverage under
  `crates/cli/tests/computer_use_suite`, but that suite's `agent` lane is not live
  inference. It uses `MiniwobAgentRuntime` as a local deterministic
  `InferenceRuntime`.
- The repo already has real provider-backed inference surfaces available outside
  that suite, notably `HttpInferenceRuntime` and `VerifiedHttpRuntime` wiring in
  `crates/validator/src/standard/workload/setup.rs`.
- The repo does not currently appear to contain BrowserGym, WorkArena,
  WebArenaVerified, or OSWorld adapters/checkouts. That missing integration is now
  the highest-value gap.

Immediate goals:

1. Replace "agent lane is deterministic" with an actual live-inference browser
   benchmark path that still uses repo-real `DesktopAgentService`, `BrowserDriver`,
   runtime, and artifact surfaces.
2. Land the first browser-first external benchmark integration without introducing
   a parallel execution stack or benchmark-conditioned routing.
3. Run a small live slice, classify the first real failures, and only then decide
   which deterministic reproductions belong in `computer_use_suite`.

Exit criteria for the current phase:

- one authoritative artifact-backed run proving real provider-backed inference in a
  browser/computer-use benchmark flow
- one authoritative browser-first external smoke slice with typed success/failure
  classification
- the first live-discovered product gap either fixed or explicitly classified as a
  true repo-external blocker
- the next frontier after browser-first discovery clearly defined in this document

## Validation status

Historical local baselines that remain valid but are no longer the active product
discovery metric:

- MiniWoB runtime-covered realistic tranche: `agent 25/25` under
  `crates/cli/target/computer_use_suite/run-1773396334/agent`
- broader realistic regression rung: `runtime 32/32` under
  `crates/cli/target/computer_use_suite/run-1773380341/runtime` and `agent 32/32`
  under `crates/cli/target/computer_use_suite/run-1773379509/agent`
- local workflow ladder:
  - rung 10 `workflow`: `oracle 2/2`, `runtime 2/2`, `agent 2/2` under
    `crates/cli/target/computer_use_suite/run-1773409060/{oracle,runtime,agent}`
  - rung 11 `workflow_rich`: `oracle 2/2`, `runtime 2/2`, `agent 2/2` under
    `crates/cli/target/computer_use_suite/run-1773417841/{oracle,runtime,agent}`
  - rung 12 `workflow_audit`: `oracle 2/2`, `runtime 2/2`, `agent 2/2` under
    `crates/cli/target/computer_use_suite/run-1773420009/{oracle,runtime,agent}`
  - rung 13 `workflow_mutation`: `oracle 2/2`, `runtime 2/2`, `agent 2/2` under
    `crates/cli/target/computer_use_suite/run-1773423125/{oracle,runtime,agent}`
  - rung 14 `workflow_reorder`: `oracle 2/2`, `runtime 2/2`, `agent 2/2` under
    `crates/cli/target/computer_use_suite/run-1773426492/{oracle,runtime,agent}`

Live-inference validation status:

- No authoritative live browser/computer-use inference benchmark artifacts are
  recorded yet.
- This absence is the main reason for the methodology pivot.

Required first validations for the new plan:

1. Prove that the active benchmark path is using a real provider-backed inference
   runtime rather than `MiniwobAgentRuntime`, `MockInferenceRuntime`, or the
   placeholder `StandardInferenceRuntime`.
2. Prove that the browser/computer-use path is still the repo's real
   `DesktopAgentService` plus `BrowserDriver` stack.
3. Record an authoritative browser-first smoke run with exact command, provider,
   model, env/task list, artifact root, screenshots, kernel events, and typed
   postconditions.

Validation rules for new work:

- Do not count deterministic local `computer_use_suite` passes as live-inference
  benchmark evidence.
- Do not count UI motion, browser logs, or page transitions alone as success.
- Success requires typed receipts, typed observations, typed postconditions, and
  artifact-backed verification.
- Diagnostic partial runs must be marked non-authoritative and must not move ladder
  state on their own.

## Known failures / unrelated issues

- `computer_use_suite` `agent` mode is currently deterministic by construction and
  therefore not suitable as the primary discovery lane for live product capability
  evaluation.
- `StandardInferenceRuntime` in
  `crates/validator/src/standard/workload/runtime.rs` currently returns a
  placeholder response and is not acceptable as proof of live inference.
- No BrowserGym, WorkArena, WebArenaVerified, or OSWorld integration is currently
  visible in repo search results.
- The historical full MiniWoB catalog pair remains `oracle 63/130` under
  `crates/cli/target/computer_use_suite/run-1773368165/oracle` and `runtime
  63/130` under `crates/cli/target/computer_use_suite/run-1773369088/runtime`.
  Those numbers remain historically correct, but they are not the current product
  discovery metric.
- Repo-wide warnings and unrelated dirty-worktree changes may still exist and
  should not be confused with live benchmark capability signals.

## Date-stamped implementation notes

- 2026-03-13: Retired the old "expand deterministic `computer_use_suite` frontier"
  plan as the primary roadmap. The deterministic suite now becomes regression and
  reproduction infrastructure rather than the main discovery lane.
- 2026-03-13: Confirmed from repo code that `computer_use_suite` `agent` mode uses
  `MiniwobAgentRuntime` as the active `InferenceRuntime`, which means current
  `agent` results are not live-model results.
- 2026-03-13: Confirmed from repo code that provider-backed inference plumbing
  already exists in the validator workload setup via `HttpInferenceRuntime` and
  `VerifiedHttpRuntime`. The next plan should reuse that real inference path rather
  than build a benchmark-specific inference stack.
- 2026-03-13: Established the new lane hierarchy:
  - discovery lane: live inference on browser-first external benchmarks
  - reproduction lane: deterministic local reproductions only after a live failure
    proves the gap is reusable
  - regression lane: MiniWoB plus local workflow fixtures as CI and confidence
    coverage
- 2026-03-13: Preserved CIRC and CEC invariants as non-negotiable. The pivot does
  not authorize benchmark-conditioned routing, static provider ladders, task-name
  heuristics, or benchmark-specific winner logic.
- 2026-03-13: The first active product question is no longer "how many more
  deterministic local tasks can we close?" It is now "what fails first under live
  browser-first inference, and which of those failures are reusable product gaps?"

## Benchmark Snapshot

Active discovery benchmarks:

| Benchmark lane | Status | Authoritative result | Artifact root | Notes |
| --- | --- | --- | --- | --- |
| Live browser-first external benchmark | not started | none | none | this is the current active frontier |
| Live cross-app external benchmark | not started | none | none | blocked on browser-first lane maturity |

Regression and reproduction baselines:

| Benchmark lane | Status | Authoritative result | Artifact root | Notes |
| --- | --- | --- | --- | --- |
| MiniWoB runtime-covered realistic tranche | closed baseline | `agent 25/25` | `crates/cli/target/computer_use_suite/run-1773396334/agent` | keep for regression, not active discovery |
| MiniWoB broader realistic regression rung | closed baseline | `runtime 32/32`, `agent 32/32` | `crates/cli/target/computer_use_suite/run-1773380341/runtime`, `crates/cli/target/computer_use_suite/run-1773379509/agent` | do not use as live-inference evidence |
| Local workflow rung 10 | closed baseline | `2/2, 2/2, 2/2` | `crates/cli/target/computer_use_suite/run-1773409060/{oracle,runtime,agent}` | deterministic local browser workflow |
| Local workflow rung 11 | closed baseline | `2/2, 2/2, 2/2` | `crates/cli/target/computer_use_suite/run-1773417841/{oracle,runtime,agent}` | richer deterministic local workflow |
| Local workflow rung 12 | closed baseline | `2/2, 2/2, 2/2` | `crates/cli/target/computer_use_suite/run-1773420009/{oracle,runtime,agent}` | audit/history deterministic local workflow |
| Local workflow rung 13 | closed baseline | `2/2, 2/2, 2/2` | `crates/cli/target/computer_use_suite/run-1773423125/{oracle,runtime,agent}` | mutation-isolation deterministic local workflow |
| Local workflow rung 14 | closed baseline | `2/2, 2/2, 2/2` | `crates/cli/target/computer_use_suite/run-1773426492/{oracle,runtime,agent}` | stale-queue reorder deterministic local workflow |

## Capability Gap Matrix

The matrix below tracks which gap classes are still product-active under the new
live-discovery methodology.

| Gap class | Current live-discovery status | Local deterministic status | Current handling |
| --- | --- | --- | --- |
| `missing_pointer_primitive` | not yet re-evaluated | dormant baseline | reopen only if live browser-first failures require it |
| `missing_selection_primitive` | not yet re-evaluated | dormant baseline | keep MiniWoB coverage; do not reopen proactively |
| `missing_keyboard_primitive` | not yet re-evaluated | dormant baseline | reopen only on live evidence |
| `missing_clipboard_primitive` | not yet re-evaluated | dormant baseline | reopen only on live evidence |
| `observation_gap` | active candidate | partially closed in local baselines | first likely live-discovery failure class |
| `verification_gap` | active candidate | partially closed in local baselines | live benchmarks must prove typed postconditions |
| `recovery_gap` | active candidate | partially closed in local baselines | expect browser-first recovery pressure before OSWorld |
| `planner_gap` | active candidate | several prior labels corrected away in local baselines | require narrow classification from artifacts, not generic fallback labels |
| `infra_or_bridge_gap` | active candidate | known from prior local diagnostics | must be separated from product gaps before ladder state changes |

Interpretation rules:

- "not yet re-evaluated" means the class is not currently active evidence, not that
  it is solved forever.
- "dormant baseline" means the repo has prior deterministic coverage, but that
  coverage does not prove the class is closed under live inference.
- Every live failure must be narrowed to the smallest honest class before it can be
  used to justify tooling work or deterministic reproduction work.

## Benchmark Escalation Ladder

The retired ladder that ended in deterministic local workflow rung 14 is now a
historical baseline. The active ladder resets around the new discovery
methodology.

1. Live inference plumbing proof
   Status: pending.
   Objective:
   - prove the browser/computer-use agent is invoking a real provider-backed
     inference runtime
   Requirements:
   - reuse repo-real `DesktopAgentService`, `BrowserDriver`, and workload/runtime
     surfaces
   - do not use `MiniwobAgentRuntime`, `MockInferenceRuntime`, or the placeholder
     `StandardInferenceRuntime`
   - record provider, model, runtime kind, exact command, and artifact root
   Exit criteria:
   - one authoritative artifact-backed run proving live inference is actually in
     the loop

2. Browser-first adapter bring-up
   Status: pending.
   Objective:
   - land the smallest viable BrowserGym-style integration on the existing repo
     stack
   Preferred targets:
   - WorkArena first if it is the lightest realistic path
   - WebArenaVerified first if its verification surfaces are easier to make typed
   Requirements:
   - no parallel execution stack
   - no benchmark-conditioned routing or task-name hacks
   - use typed observations and typed postconditions
   Exit criteria:
   - authoritative smoke slice runs end to end on a live browser-first benchmark

3. Browser-first live smoke slice
   Status: pending.
   Objective:
   - run a small authoritative live-inference slice and classify the first real
     failures
   Minimum output:
   - exact commands
   - provider/model/env metadata
   - task ids
   - artifact roots
   - screenshots
   - kernel events
   - typed receipts or typed failure postconditions
   Exit criteria:
   - either at least one real reusable product gap is identified, or the slice
     passes cleanly and the next harder browser-first slice is defined

4. Shared browser-first gap closure
   Status: pending.
   Objective:
   - close the first live-discovered reusable browser/computer-use gap using shared
     tooling/runtime/observation/recovery improvements
   Requirements:
   - fix the product issue in shared surfaces, not in benchmark-local routing
   - rerun the failing task and then a broader slice
   Exit criteria:
   - authoritative rerun passes and the broader slice does not regress

5. Deterministic reproduction backfill
   Status: pending.
   Objective:
   - add deterministic local coverage only for live-discovered reusable failures
   Requirements:
   - every new deterministic case must cite the live failure artifact root that
     justified it
   Exit criteria:
   - the live-discovered gap now has stable regression protection

6. Browser-first exhaustion checkpoint
   Status: pending.
   Objective:
   - determine whether browser-first live discovery is still yielding product
     signal
   Exit criteria:
   - either continue browser-first escalation, or define the next frontier as
     cross-app OSWorld / OSWorld-Verified

7. Cross-app escalation
   Status: pending.
   Objective:
   - move to OSWorld / OSWorld-Verified after browser-first discovery reaches a
     stable checkpoint
   Requirements:
   - keep the same artifact discipline and classification rules
   - prefer shared fixes over benchmark-local workarounds
   Exit criteria:
   - first authoritative cross-app smoke slice recorded, or a true repo-external
     blocker documented

## Iteration Update Protocol

This file is the single authoritative backlog, status ledger, and living roadmap
for browser/computer-use discovery work.

For every meaningful iteration:

1. Update `Status` and `Benchmark Escalation Ladder` first so a fresh agent knows
   the active frontier before reading old notes.
2. Record exact commands, provider/runtime configuration, benchmark/task ids,
   artifact roots, and whether the run is diagnostic or authoritative.
3. For every failure, record:
   - exact failure task
   - env and seed when applicable
   - reward or judge outcome
   - kernel events
   - screenshots
   - browser observations
   - typed postconditions that failed
   - corrected gap classification
4. Do not claim success from motion, screenshots, or logs alone. Require typed
   receipts, typed observations, or typed postconditions.
5. If a live run discovers a reusable gap, prefer a shared fix in runtime,
   observation, verification, recovery, or bridge surfaces before adding any
   deterministic reproduction.
6. Add deterministic `computer_use_suite` coverage only after a live failure proves
   the gap is real and reusable.
7. When a rung appears green, rerun the exact failing slice first, then run a
   broader slice before calling the rung stable.
8. If a failure is due to benchmark checkout, licensing, unavailable credentials,
   missing vendor infra, or another true repo-external blocker, record that
   blocker explicitly and stop escalation only at that point.
9. Keep historical deterministic baselines recorded, but do not let them replace
   live discovery evidence in summaries or decision-making.
10. When the browser-first frontier reaches exhaustion, define the next frontier
    explicitly before ending the iteration.

Decision rules:

- Discovery work should be prioritized by live product signal, not by ease of
  writing another deterministic task.
- MiniWoB and local workflow additions are justified only when they protect a
  shared reusable capability that was first exposed by live external runs.
- If browser-first live runs are unavailable because the repo lacks an adapter,
  the immediate task is to land the adapter on existing repo surfaces, not to
  continue expanding deterministic local workflow ladders.
