# MiniWoB-Backed `computer_use_suite` Plan

## Goal

Create a MiniWoB-backed `computer_use_suite` that measures browser/computer-use reliability without distorting the runtime toward unrealistic DOM-only shortcuts. The suite should complement, not replace, the existing `capabilities_suite`.

Primary outcomes:

- benchmark browser/computer-use primitives against a repeatable task corpus
- catch regressions in tool routing, browser action execution, and recovery behavior
- produce artifacts that make failures debuggable
- provide an upper bound (`oracle`) and realistic runtime benchmark (`runtime` and `agent`)

## Why MiniWoB

MiniWoB++ is a good fit because it provides:

- a large catalog of web interaction tasks
- per-episode instruction text
- observations including screenshot and visible DOM metadata
- configurable action spaces for click, scroll, keypress, typing, and element-based actions
- reward and termination signals

That makes it useful for validating browser interaction quality before expanding more UI-heavy capabilities. It is not a substitute for wrapper rollout validation or the broader product-level capability suite.

## Non-Goals

- replacing `capabilities_suite`
- blocking step 5 wrapper rollout on MiniWoB completion alone
- teaching the runtime to depend on MiniWoB-only shortcuts in production
- solving every MiniWoB task class in the first pass

## Existing Repo Surfaces To Reuse

The suite should reuse existing harness and runtime components rather than introducing a parallel stack:

- `crates/cli/tests/capabilities_suite/harness/case_runner.rs`
- `crates/cli/tests/reliability_suite/harness.rs`
- `crates/services/src/agentic/desktop/execution/browser/handler.rs`
- `crates/drivers/src/browser/dom_ops/js_helpers.rs`

Important existing browser actions already map cleanly to a realistic MiniWoB runtime:

- `browser__snapshot`
- `browser__click_element`
- `browser__synthetic_click`
- `browser__scroll`
- `browser__type`
- `browser__key`
- `browser__wait`

## Architecture

Split the system into three layers:

1. MiniWoB bridge
   - owns task sessions, seeds, reset, reward, termination, and page URL
   - runs outside the Rust harness as a local helper process
   - exposes a thin localhost API

2. Rust suite harness
   - starts bridge sessions
   - launches browser runtime
   - drives actions through existing tool surfaces
   - captures kernel events, workload receipts, screenshots, and artifacts

3. Judge/reporting layer
   - scores task success
   - scores kernel behavior
   - writes per-run JSONL plus aggregate summaries

Recommended bridge contract:

- `POST /session/create`
- `POST /session/{id}/reset`
- `GET /session/{id}/state`
- `GET /session/{id}/url`
- `POST /session/{id}/oracle_step`
- `POST /session/{id}/close`

`state` should include at least:

- `env_id`
- `seed`
- `utterance`
- `reward`
- `terminated`
- `truncated`
- `episode_step`
- `info`

## Execution Modes

The suite should support three modes from the start.

### `oracle`

Purpose:

- validate the MiniWoB bridge and task manifest
- establish an upper bound independent of planner/runtime weakness

Rules:

- MiniWoB-native shortcut actions are allowed
- results should not be treated as the real product benchmark

### `runtime`

Purpose:

- benchmark the current browser/computer tool surface directly

Rules:

- no MiniWoB shortcut execution
- actions must be mapped onto real repo tools
- success and failure should be attributable to the same primitives used by the agent

Allowed actions should map to:

- coordinate click
- semantic element click
- scroll
- type text
- key press
- wait

### `agent`

Purpose:

- benchmark end-to-end planning plus tool execution using the same realistic action surface

Rules:

- use `DesktopAgentService`
- allow the planner to choose tools
- judge both task completion and execution quality

## Proposed Suite Layout

Create a sibling suite to `capabilities_suite`:

- `crates/cli/tests/computer_use_suite/mod.rs`
- `crates/cli/tests/computer_use_suite/harness.rs`
- `crates/cli/tests/computer_use_suite/types.rs`
- `crates/cli/tests/computer_use_suite/judge.rs`
- `crates/cli/tests/computer_use_suite/tasks/mod.rs`
- `crates/cli/tests/computer_use_suite/tasks/smoke.rs`
- `crates/cli/tests/computer_use_suite/tasks/core.rs`
- `crates/cli/tests/computer_use_suite/tasks/stress.rs`
- `crates/cli/tests/computer_use_suite_e2e.rs`

Bridge/helper tooling:

- `tools/miniwob/bridge.py`
- `tools/miniwob/requirements.txt`
- optionally `tools/miniwob/README.md`

## Data Model

Define a suite-local case type instead of reusing `QueryCase`.

Suggested fields for `ComputerUseCase`:

- `id`
- `env_id`
- `seed`
- `mode`
- `task_set`
- `max_steps`
- `timeout_seconds`
- `allowed_tool_profile`
- `expected_reward_floor`
- `expected_pass`
- `local_judge`

Suggested observation model:

- task metadata
- utterance
- final reward
- terminated/truncated flags
- executed tools
- workload receipts
- workload activity counts
- browser screenshots
- browser snapshot excerpts
- failure class summary
- per-step action log

## Task Selection

Start narrow. The first slice should validate the harness and the core browser primitives.

### Phase 1 `smoke`

Target 8-10 tasks:

- click-button
- click-link
- enter-text
- focus-text
- choose-list
- click-tab
- use-autocomplete
- scroll-text

### Phase 2 `core`

Expand to 15-25 tasks:

- forms
- menu and tab navigation
- autocomplete variants
- inbox-like tasks
- layout-transfer variants
- multi-step flows with scrolling and typing

### Phase 3 `stress`

Add harder tasks only after the suite is stable:

- longer horizon tasks
- multi-widget tasks
- tasks sensitive to focus or incremental state changes

## Action Mapping

The benchmark is only useful if `runtime` and `agent` reflect the real runtime.

Preferred mappings:

- MiniWoB click target -> `browser__click_element` when semantic IDs are available
- MiniWoB coordinate click -> `browser__synthetic_click`
- MiniWoB typing -> `browser__type`
- MiniWoB keypress -> `browser__key`
- MiniWoB scroll -> `browser__scroll`
- MiniWoB passive state stabilization -> `browser__wait`

Use browser-side JS evaluation only for read-only probes, diagnostics, or task-state inspection. Do not expose it as the primary action path in `runtime` or `agent`.

## Scoring

Score each run on two independent axes.

### Task Success

- reward
- pass/fail at episode end
- step count
- wall clock time
- retries or recovery behavior

### Kernel Behavior

- tool sequence quality
- receipt coverage
- lifecycle event coverage
- duplicate event detection
- no-effect recovery
- stable failure classification

The suite should fail runs for either:

- task not completed
- kernel behavior contract violated even if reward is positive

## Artifacts

Persist artifacts for every failed run and optionally all runs in verbose mode.

Required artifacts:

- `env_id`
- `seed`
- mode
- utterance
- final reward
- termination state
- per-step tool log
- kernel event log
- workload receipt log
- browser screenshots
- browser snapshot XML excerpts
- bridge state dump

Suggested output formats:

- per-run `jsonl`
- aggregate markdown summary
- optional CSV for trend dashboards

## Implementation Phases

### PR1: Suite Scaffold

- add `computer_use_suite` module tree
- add `ComputerUseCase` and observation structs
- add test entrypoint and task manifest loader
- add compile-only integration target

### PR2: MiniWoB Bridge

- add Python bridge process and dependency manifest
- implement session create/reset/state/url/close
- support deterministic seeds
- verify one smoke task in `oracle` mode

### PR3: Runtime Mode

- wire MiniWoB page URLs into `BrowserDriver`
- implement realistic action mapping onto browser tools
- capture artifacts and kernel events
- add smoke task set for direct runtime execution

### PR4: Agent Mode

- route tasks through `DesktopAgentService`
- add judge logic for task success plus kernel behavior
- add ignored E2E runs for smoke tasks

### PR5: Core Expansion And CI

- expand to the `core` task set
- add aggregate reporting
- add helper scripts for local and CI runs
- document prerequisites and expected artifacts

## Status

Current phase:

- complete as of 2026-03-12

Completed phases:

- PR1 complete: sibling `computer_use_suite` module tree, typed case/result models, task manifests, judge, harness, and test target landed under `crates/cli/tests`
- PR2 complete: Python MiniWoB bridge landed under `tools/miniwob` with deterministic seeded session lifecycle, local `file://` task materialization, state sync, and oracle-step support
- PR3 complete: direct `runtime` mode drives MiniWoB through repo browser/computer-use tools, captures artifacts, and passes the smoke slice
- PR4 complete: `agent` mode routes through `DesktopAgentService`, enforces local judging on reward plus kernel behavior, and passes the smoke slice
- PR5 complete: `core` and `stress` manifests are populated, aggregate JSONL/CSV/Markdown reporting is emitted, helper scripts exist for local and CI-oriented runs, and bridge/docs were updated

Remaining phases:

- none

Decisions made:

- kept `computer_use_suite` as a sibling of `capabilities_suite`; no capability-suite coupling was introduced
- preserved CIRC/CEC invariants by keeping intent/capability/tool boundaries intact and using a deterministic suite-local inference runtime instead of semantic routing patches
- limited MiniWoB-native shortcuts to `oracle`; `runtime` and `agent` only use repo-real browser/computer-use tools for actions
- used MiniWoB bridge state as the authoritative verification/evidence feed and persisted bridge state, kernel events, screenshots, and agent state on failures
- added an env-driven ignored test entrypoint plus `tools/miniwob/run_suite.sh` and `tools/miniwob/run_ci_smoke.sh` so local and CI flows can run arbitrary mode/task-set combinations

Deviations from original plan:

- realistic modes do not depend on `browser__snapshot` for primary element discovery on MiniWoB `file://` pages because Chromium AX tree snapshots intermittently fail with `CDP GetAxTree failed: notRendered`; the suite instead uses bridge-discovered selectors for action targeting and keeps snapshots for diagnostics only
- the bridge exposes an additional `/health` probe and page-driven `/sync` endpoint to make sidecar startup and browser-state synchronization deterministic

Validation status:

- `cargo test -p ioi-cli --test computer_use_suite_e2e --no-run` passed on 2026-03-12
- `cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_manifest_is_unique -- --nocapture` passed on 2026-03-12
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_oracle_smoke -- --ignored --nocapture` passed on 2026-03-12 (`pass=8/8`)
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_runtime_smoke -- --ignored --nocapture` passed on 2026-03-12 (`pass=8/8`)
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_agent_smoke -- --ignored --nocapture` passed on 2026-03-12 (`pass=8/8`)
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=core COMPUTER_USE_SUITE_CASES=miniwob_click_option_core tools/miniwob/run_suite.sh` passed on 2026-03-12 (`pass=1/1`)

Known failures / unrelated issues:

- no suite-specific validation failures remain in the exercised matrix above
- repository-wide compiler/test warnings remain noisy but are pre-existing and unrelated to this suite landing
- test artifact setup logs `cargo-component` as missing and skips building `crates/cli/tests/fixtures/mock-verifier`; the MiniWoB suite still passes without that artifact

Date-stamped implementation notes:

- 2026-03-12: added the full `crates/cli/tests/computer_use_suite` scaffold, smoke/core/stress manifests, per-run judging, artifact persistence, and aggregate JSONL/CSV/Markdown reports
- 2026-03-12: added `tools/miniwob/bridge.py`, `requirements.txt`, and README-backed bridge workflow for deterministic local MiniWoB execution
- 2026-03-12: implemented `oracle`, `runtime`, and `agent` execution paths, including MiniWoB-native oracle sanity steps and repo-real browser/computer-use actions for realistic modes
- 2026-03-12: hardened agent incident recovery for scroll and dropdown flows so smoke tasks no longer fail on duplicate-action or forbidden-recovery incidents
- 2026-03-12: added env-driven helper entrypoints and scripts for local/CI runs (`computer_use_suite_from_env`, `tools/miniwob/run_suite.sh`, `tools/miniwob/run_ci_smoke.sh`)

## CI Strategy

Stage this gradually.

Compile-only gate:

```bash
cargo test -p ioi-cli --test computer_use_suite_e2e --no-run
```

Runtime gate:

- ignored by default
- requires Chromium runtime and Python dependencies for MiniWoB

Optional nightly matrix:

- `oracle` smoke
- `runtime` smoke
- `agent` smoke
- selected `core` tasks

## Risks And Guardrails

### Risk: Unrealistic Benchmarking

If `runtime` or `agent` rely on MiniWoB element shortcuts, the suite will overstate real product performance.

Guardrail:

- restrict shortcuts to `oracle`
- keep `runtime` and `agent` on current browser/computer tools only

### Risk: Bridge Flakiness

A fragile Python sidecar can make the suite noisy.

Guardrail:

- keep the API thin
- make session lifecycle explicit
- persist bridge state on failure

### Risk: Signal Dilution

If the suite starts with too many tasks, failures will be expensive to debug.

Guardrail:

- start with a small smoke set
- require artifact capture from the first PR

### Risk: Overlap Confusion With `capabilities_suite`

MiniWoB can be mistaken for the main product benchmark.

Guardrail:

- document that `computer_use_suite` is a browser/computer-use reliability benchmark
- keep `capabilities_suite` as the product-level evaluation suite

## Done When

Step completion for this initiative should mean:

- one command runs a MiniWoB-backed suite locally
- `oracle`, `runtime`, and `agent` share the same task manifest
- `runtime` uses only realistic repo browser/computer tools
- the suite emits actionable artifacts for failures
- smoke tasks are stable enough to detect regressions
- the suite is ready to harden browser/computer-use behavior before expanding additional UI-heavy capabilities

## Sources

- <https://miniwob.farama.org/index.html>
- <https://miniwob.farama.org/content/observation_space/>
- <https://miniwob.farama.org/content/action_space/>
- <https://miniwob.farama.org/content/reward/>
- <https://miniwob.farama.org/content/javascript_api/>
