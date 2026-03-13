# MiniWoB-Backed `computer_use_suite` Plan

## Goal

Create and iteratively harden a MiniWoB-backed `computer_use_suite` that measures browser/computer-use reliability without distorting the runtime toward unrealistic DOM-only shortcuts. The suite should complement, not replace, the existing `capabilities_suite`.

Primary outcomes:

- benchmark browser/computer-use primitives against a repeatable task corpus
- catch regressions in tool routing, browser action execution, and recovery behavior
- produce artifacts that make failures debuggable
- provide an upper bound (`oracle`) and realistic runtime benchmark (`runtime` and `agent`)
- use MiniWoB failure pressure to force generic primitive and observation expansion in the real browser/computer-use stack
- maintain a separate benchmark-oriented parity candidate lane without leaking benchmark-specific shortcuts into product routing or capability logic

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
- introducing benchmark-specific heuristics, keyword routing, or task-name-specific hacks in product intent/capability logic
- treating a full-catalog MiniWoB candidate as equivalent to overall product correctness

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

### `candidate` (continuation lane)

Purpose:

- pursue broad MiniWoB coverage and a possible full-catalog passing candidate without contaminating product runtime policy

Rules:

- use the same real browser/computer-use tool substrate as `runtime` and `agent`
- keep it benchmark-only and separately reported from product-facing `agent`
- allow benchmark-oriented prompt/policy/runtime tuning, but not MiniWoB-native action shortcuts outside `oracle`
- do not add query-conditioned ladders or benchmark-specific semantic winner selection to product intent logic

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

## Primitive Expansion Targets

MiniWoB should now be used to force the next generic tool tranche into the open.

Priority order:

- pointer semantics: hover, pointer move, mouse down, mouse up, and drag composed from those primitives
- selection semantics: text selection, selection range extension, and focused selection state inspection
- keyboard semantics: key chords, modifier-aware input, focus traversal, and more explicit submit/escape behavior
- clipboard semantics: copy, cut, paste, and typed receipts proving state transition
- observation fallbacks: stronger AX reliability, DOM/selector-state fallback, and screenshot/OCR-backed diagnostics
- verification receipts: typed postconditions for pointer, selection, and focus-changing actions

The benchmark should push generic tool evolution. It must not be solved by MiniWoB-only adapters in realistic modes.

## Capability Gap Taxonomy

Every runtime or agent failure outside obvious infra issues should be tagged with one primary gap class.

Primary classes:

- `missing_pointer_primitive`
- `missing_selection_primitive`
- `missing_keyboard_primitive`
- `missing_clipboard_primitive`
- `observation_gap`
- `verification_gap`
- `recovery_gap`
- `planner_gap`
- `infra_or_bridge_gap`

Secondary tags may record the concrete missing capability, for example:

- `hover`
- `drag`
- `mouse_down_up`
- `selection_range`
- `key_chord`
- `clipboard`
- `iframe_targeting`
- `shadow_root_targeting`
- `ocr_readback`
- `focus_traversal`

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

## Continued Iteration Plan

The initial suite landing is complete. The continuation backlog below is now the authoritative roadmap for further work.

### PR6: Full-Catalog Baseline And Gap Matrix

- run broad `oracle` coverage across the MiniWoB catalog to establish the harness upper bound
- run broad `runtime` coverage across the same catalog and classify each failure by primary gap class plus secondary tags
- record per-task support state as one of:
  - `passing`
  - `known_gap`
  - `infra_blocked`
  - `not_yet_attempted`
- add a benchmark snapshot section to this document with pass counts for `oracle`, `runtime`, `agent`, and later `candidate`
- ensure every non-passing task has an artifact bundle and machine-readable failure class

Validation:

- full-catalog `oracle` summary captured
- broad `runtime` summary captured
- gap matrix written down in this document or a linked machine-readable artifact

### PR7: Pointer Primitive Tranche

- add generic pointer primitives for hover, pointer move, mouse down, and mouse up
- support drag by composing those primitives rather than adding a benchmark-specific drag shortcut
- add typed receipts and postconditions for pointer target acquisition, press state, drag source, drag destination, and resulting DOM/UI state
- expand the suite with hover-sensitive and drag-sensitive task slices

Validation:

- compile-only coverage for new tool contracts
- targeted MiniWoB tasks covering hover and drag pass in `runtime`
- no new benchmark-specific shortcuts introduced in realistic modes

### PR8: Selection, Keyboard, Clipboard, And Focus Tranche

- add selection-range and text-selection primitives
- add or extend modifier-aware key-chord support
- add clipboard primitives and receipts
- harden focus traversal behavior for tab order, escape, enter, and submit flows
- expand task coverage for selection-heavy, keyboard-heavy, and clipboard-sensitive tasks

Validation:

- targeted MiniWoB tasks covering text selection and keyboard-heavy flows pass in `runtime`
- receipts prove state transitions instead of relying on UI movement or final text alone

### PR9: Observation Hardening

- make `browser__snapshot` and related read paths more reliable on `file://`, delayed-render, iframe, and awkward AX states
- add structured DOM/selector-state fallback for observation when AX data is unavailable
- add screenshot/OCR-backed diagnostics and optional read-only observation fallback where DOM semantics are weak
- persist observation provenance so failures show which read path was used

Validation:

- observation fallback path is exercised in tests
- failure artifacts clearly indicate whether AX, DOM, or OCR-backed observation was used

### PR10: Recovery And Verification Hardening

- generalize receipt-driven no-effect detection for the new primitives
- strengthen completion gating so success depends on typed observations and required postconditions
- keep failures stable and machine-readable rather than retrying heuristically in the real environment
- tighten kernel behavior scoring around duplicate actions, stale reads, and unsupported tool use

Validation:

- new primitive receipts are covered by judge logic
- recovery behavior improves pass rate without introducing heuristic sandbox retries

### PR11: Runtime Coverage Expansion And Nightly Regression Tracking

- promote task families from `known_gap` to `passing` only when the underlying primitive or observation gap is actually closed
- expand nightly runs from smoke/core into broader slices grouped by capability family
- add trend reporting for pass rate by task family, gap class, and mode
- keep `runtime` and `agent` as the main regression lanes for the real product tool substrate

Validation:

- nightly reports show pass/fail deltas by capability family
- regressions are attributable to concrete primitive or observation changes

### PR12: Separate Full-Catalog Candidate Lane

- add a benchmark-only `candidate` lane that runs on the same generic browser/computer-use primitives as `runtime` and `agent`
- allow benchmark-oriented prompt, policy, or runtime tuning in that lane only
- optionally leverage successful `oracle` and `runtime` traces as training or prompting material
- compare `candidate` separately from `runtime` and `agent`; do not let it replace the product-facing regression lanes

Validation:

- `candidate` uses the same real tool substrate as `runtime`
- `candidate` reporting is clearly separated from product-facing lanes
- any full-catalog pass claim is backed by artifacts and mode-specific summaries

## Status

Current phase:

- PR8 selection, keyboard, clipboard, and focus tranche is now fully closed in realistic modes as of 2026-03-13.
- PR11 runtime and agent coverage expansion is now the active phase. The next benchmark frontier is no longer low-level primitive parity; it is broader agent coverage on catalog families the direct runtime already solves generically.
- The broader PR8 realistic regression rung is now green in both lanes: `runtime 32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime` and `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`.
- Agent coverage moved materially beyond the old curated slice during this iteration: `agent 7/7` at `crates/cli/target/computer_use_suite/run-1773381666/agent` for `simple-arithmetic`, `simple-algebra`, `odd-or-even`, `find-word`, `read-table`, `read-table-2`, and `phone-book`.
- The latest authoritative full discovered-catalog pair is still `oracle 63/130` at `crates/cli/target/computer_use_suite/run-1773368165/oracle` and `runtime 63/130` at `crates/cli/target/computer_use_suite/run-1773369088/runtime`. A fresh full runtime recapture is still pending; the current targeted and broader slices prove that the former `click-tab-2*` misses are now closed, but that has not yet been rolled into a new full-catalog total.
- PR7 pointer work remains complete and should not be reopened wholesale. The current benchmark pressure is on planner/recipe breadth plus remaining survey-only catalog families, not on the low-level pointer/selection substrate landed in PR7 and PR8.

Completed phases:

- PR1 complete: sibling `computer_use_suite` module tree, typed case/result models, task manifests, judge, harness, and test target landed under `crates/cli/tests`
- PR2 complete: Python MiniWoB bridge landed under `tools/miniwob` with deterministic seeded session lifecycle, local `file://` task materialization, state sync, and oracle-step support
- PR3 complete: direct `runtime` mode drives MiniWoB through repo browser/computer-use tools, captures artifacts, and passes the smoke slice
- PR4 complete: `agent` mode routes through `DesktopAgentService`, enforces local judging on reward plus kernel behavior, and passes the smoke slice
- PR5 complete: `core` and `stress` manifests are populated, aggregate JSONL/CSV/Markdown reporting is emitted, helper scripts exist for local and CI-oriented runs, and bridge/docs were updated
- PR6 complete: discovered full-catalog `oracle` and `runtime` baselines were captured, a first broad catalog `agent` slice was recorded, and the gap matrix/benchmark ledger now tracks support state plus primary/secondary capability gaps
- PR7 complete: real browser pointer primitives (`hover`, `pointer_move`, `mouse_down`, `mouse_up`, composed `drag`) landed with typed receipts/postconditions, targeted pointer tasks pass in `oracle` and `runtime`, and the broad benchmark moved materially after the tranche
- PR8 complete: selection-range support, modifier-aware key chords, clipboard flows, focus/startup hardening, duplicate-wait dedupe hardening, one-shot startup navigation for agent mode, zero-floor completion gating fixes, and the PR8 closure slices all landed with code, tests, docs, and broader realistic-mode validation

Remaining phases:

- PR9: observation hardening if a fresh broad/full recapture exposes a real observation-led family again
- PR10: recovery and verification hardening
- PR11: runtime and agent coverage expansion plus nightly regression tracking
- PR12: separate full-catalog candidate lane

Decisions made:

- kept `computer_use_suite` as a sibling of `capabilities_suite`; no capability-suite coupling was introduced
- preserved CIRC/CEC invariants by keeping intent/capability/tool boundaries intact and using a deterministic suite-local inference runtime instead of semantic routing patches
- limited MiniWoB-native shortcuts to `oracle`; `runtime`, `agent`, and future `candidate` work only use repo-real browser/computer-use tools for actions
- used MiniWoB bridge state as the authoritative verification/evidence feed and persisted bridge state, kernel events, screenshots, and agent state on failures
- decided to use MiniWoB parity pressure as a forcing function for generic primitive and observation expansion rather than as justification for benchmark-specific shortcuts
- decided that any future full-catalog passing push should live in a separate `candidate` lane built on the same real tool substrate as `runtime` and `agent`
- one real `browser__navigate` must be issued in agent mode before bridge-readiness waits are trusted; `bridge_state.info.page_url` alone is not enough to prove the browser actually navigated
- zero-floor reward tasks must not short-circuit either the outer agent loop or `MiniwobAgentRuntime::next_action`; completion gating must use the same explicit zero-floor helper in both places
- adjacent `browser__wait` actions are a valid control-flow primitive during startup/recovery and must be exempt from the generic immediate-replay dedupe that applies to other non-command tools
- authoritative benchmark runs should be taken serially; overlapping suite invocations can reuse the same timestamp root and make debugging harder even when the underlying code is correct
- once a tranche closes its targeted slice, it must immediately earn at least one broader `runtime` and one broader `agent` recapture before the phase can be marked complete
- partial diagnostic runs must be called out explicitly and left non-authoritative; the aborted full-agent diagnostic at `crates/cli/target/computer_use_suite/run-1773380439/agent` and the aborted combined 39-case agent diagnostic at `crates/cli/target/computer_use_suite/run-1773381814/agent` should not be treated as benchmark state
- the next high-yield agent work should port runtime-covered catalog families before opening new survey-only recipes; the latest iteration followed that rule by adding agent coverage for text-and-logic families already solved in direct mode

Deviations from original plan:

- the bridge exposes an additional `/health` probe and page-driven `/sync` endpoint to make sidecar startup and browser-state synchronization deterministic
- `cargo test` runs the suite from `crates/cli`, so baseline artifact roots emitted as `target/computer_use_suite/...` resolve under `crates/cli/target/computer_use_suite/...`
- realistic modes still avoid `browser__snapshot` as a primary action dependency on MiniWoB `file://` pages because Chromium AX snapshots can be unreliable there; bridge state and real browser primitives remain the authoritative action substrate
- PR8 started exactly where the benchmark isolated the next missing generic primitives: `highlight-text` (`selection_range`) and `copy-paste` (`clipboard`, `key_chord`)
- PR8 had to absorb two generic agent/runtime control-flow fixes that were not obvious from the original tranche definition but were required for truthful validation:
  - one-shot startup navigation in agent mode
  - zero-floor completion gating in both the outer agent loop and `next_action`
- the hover-only agent reruns briefly looked like PR8 regressions, but after removing the startup/zero-floor false positives they resolved back to the real remaining pointer issue: hover verification still reports `hovered=false` on `#highlight`
- the next post-PR8 movement came from agent-visible-text parsing and selector-driven recipe expansion, not from opening a new primitive tranche; the current frontier is broader coverage rather than another low-level browser tool gap

Validation status:

- `cargo test -p ioi-services browser_interaction_scope_allows_pointer_followups -- --nocapture` passed on 2026-03-12 after extending browser interaction capability bindings for pointer follow-ups
- `cargo test -p ioi-cli --test computer_use_suite_e2e synthetic_kernel_events_do_not_count_as_executed_tools -- --nocapture` passed on 2026-03-12 after filtering synthetic `system::max_steps_reached` events from kernel tool accounting
- `cargo test -p ioi-services browser_wait_is_allowed_to_repeat_on_adjacent_steps -- --nocapture` passed on 2026-03-12 after exempting `browser__wait` from adjacent non-command replay blocking
- `cargo test -p ioi-cli --test computer_use_suite_e2e 'computer_use_suite::harness::tests::' -- --nocapture` passed on 2026-03-13 (`32 passed`) after adding visible-text parsing and agent recipe coverage tests for the new text-and-logic slice
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with targeted PR8 realistic-mode validation: `runtime 4/4`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773372368/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with targeted PR8 realistic-mode validation: `agent 4/4`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773372670/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_scroll_text_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with `agent 1/1`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773379418/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_click_checkboxes_soft,miniwob_catalog_scroll_text_2,miniwob_catalog_use_autocomplete COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with `agent 3/3`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773379444/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_choose_list,miniwob_catalog_click_button,miniwob_catalog_click_button_sequence,miniwob_catalog_click_checkboxes,miniwob_catalog_click_checkboxes_large,miniwob_catalog_click_checkboxes_soft,miniwob_catalog_click_checkboxes_transfer,miniwob_catalog_click_collapsible,miniwob_catalog_click_collapsible_2,miniwob_catalog_click_collapsible_2_nodelay,miniwob_catalog_click_collapsible_nodelay,miniwob_catalog_click_link,miniwob_catalog_click_option,miniwob_catalog_click_tab,miniwob_catalog_click_tab_2,miniwob_catalog_click_tab_2_easy,miniwob_catalog_click_tab_2_hard,miniwob_catalog_click_tab_2_medium,miniwob_catalog_enter_password,miniwob_catalog_enter_text,miniwob_catalog_enter_text_2,miniwob_catalog_focus_text,miniwob_catalog_focus_text_2,miniwob_catalog_login_user,miniwob_catalog_scroll_text_2,miniwob_catalog_search_engine,miniwob_catalog_use_autocomplete,miniwob_catalog_use_autocomplete_nodelay,miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with a broader realistic agent slice: `agent 32/32`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773379509/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_click_tab_2,miniwob_catalog_click_tab_2_easy,miniwob_catalog_click_tab_2_hard,miniwob_catalog_click_tab_2_medium COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with targeted `click-tab-2*` regression validation: `runtime 4/4`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773380215/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_choose_list,miniwob_catalog_click_button,miniwob_catalog_click_button_sequence,miniwob_catalog_click_checkboxes,miniwob_catalog_click_checkboxes_large,miniwob_catalog_click_checkboxes_soft,miniwob_catalog_click_checkboxes_transfer,miniwob_catalog_click_collapsible,miniwob_catalog_click_collapsible_2,miniwob_catalog_click_collapsible_2_nodelay,miniwob_catalog_click_collapsible_nodelay,miniwob_catalog_click_link,miniwob_catalog_click_option,miniwob_catalog_click_tab,miniwob_catalog_click_tab_2,miniwob_catalog_click_tab_2_easy,miniwob_catalog_click_tab_2_hard,miniwob_catalog_click_tab_2_medium,miniwob_catalog_enter_password,miniwob_catalog_enter_text,miniwob_catalog_enter_text_2,miniwob_catalog_focus_text,miniwob_catalog_focus_text_2,miniwob_catalog_login_user,miniwob_catalog_scroll_text_2,miniwob_catalog_search_engine,miniwob_catalog_use_autocomplete,miniwob_catalog_use_autocomplete_nodelay,miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with a broader direct-mode regression slice: `runtime 32/32`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_simple_arithmetic,miniwob_catalog_simple_algebra,miniwob_catalog_odd_or_even,miniwob_catalog_find_word,miniwob_catalog_read_table,miniwob_catalog_read_table_2,miniwob_catalog_phone_book COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with targeted agent coverage-expansion validation: `agent 7/7`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773381666/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=oracle COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with the current authoritative full discovered-catalog oracle snapshot: `63/130`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773368165/oracle`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with the current authoritative full discovered-catalog runtime snapshot: `63/130`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773369088/runtime`

Known failures / unrelated issues:

- repository-wide compiler/test warnings remain noisy but are pre-existing and unrelated to MiniWoB progress
- the authoritative full-catalog `runtime`/`oracle` pair is still the older `63/130` snapshot; a fresh full runtime recapture is still needed before the full-catalog totals can absorb the now-closed `click-tab-2*` family
- there is still no authoritative full-catalog `agent` total beyond the original broad baseline; the attempted all-catalog agent diagnostic at `crates/cli/target/computer_use_suite/run-1773380439/agent` was intentionally abandoned because it is too slow to be a useful iteration loop in its current form
- the aborted combined 39-case agent diagnostic at `crates/cli/target/computer_use_suite/run-1773381814/agent` is non-authoritative and should not be used for status; rely on the closed `agent 32/32` and `agent 7/7` slices instead
- the next unported runtime-covered `agent` families remain `form-sequence*`, `login-user-popup`, `text-editor`, `guess-number`, `find-greatest`, `social-media*`, `stock-market`, `email-inbox`, `visual-addition`, `identify-shape`, `count-shape`, `count-sides`, and `find-midpoint`
- survey-only full-catalog families still dominate the remaining open space in the last authoritative full pair; those have not yet been reopened as new recipes during this iteration
- authoritative benchmark runs should remain serial; overlapping or partial suite invocations make artifact roots and startup diagnosis harder

Date-stamped implementation notes:

- 2026-03-12: fixed synthetic kernel accounting, added capability bindings for the new browser pointer/selection/clipboard tools, and verified pointer-followup scope policy in `ioi-services`
- 2026-03-12: added hidden-tab selector recovery so `click-tab-2*` targeted agent runs can map a hidden target span back to its visible tab anchor without task-name-conditioned routing
- 2026-03-12: hardened `browser__hover` verification with short retry loops around selector-hover confirmation, but `hover-shape` still exposes a real remaining hover primitive issue in agent mode
- 2026-03-12: exempted adjacent `browser__wait` from duplicate non-command replay blocking so startup/recovery waits no longer self-trigger `NoEffectAfterAction`
- 2026-03-12: added one-shot startup navigation in `MiniwobAgentRuntime` because MiniWoB bridge `page_url` can be populated before the browser has actually navigated; this removed the false `task_ready=false`/`last_sync_ms=null` failures on targeted PR8 agent runs
- 2026-03-12: unified zero-floor completion gating by reusing `should_break_agent_loop_for_reward(...)` inside `next_action`; this removed the false “ready but already complete” behavior on `hover-shape`
- 2026-03-12: targeted `click-tab-2*` agent validation moved from `0/5` at `crates/cli/target/computer_use_suite/run-1773371054/agent` to `4/5` at `crates/cli/target/computer_use_suite/run-1773371794/agent`; the lone remaining failure there was `hover-shape`
- 2026-03-13: closed the broader PR8 realistic regression rung in direct mode at `runtime 32/32` under `crates/cli/target/computer_use_suite/run-1773380341/runtime`, replacing the stale `runtime 28/32` slice
- 2026-03-13: closed the matching broader PR8 realistic regression rung in agent mode at `agent 32/32` under `crates/cli/target/computer_use_suite/run-1773379509/agent`, replacing the stale `agent 26/32` slice
- 2026-03-13: added bridge-visible-text parsing plus deterministic agent recipes for `simple-arithmetic`, `simple-algebra`, `odd-or-even`, `find-word`, `read-table`, `read-table-2`, and `phone-book`; targeted live validation closed at `agent 7/7` under `crates/cli/target/computer_use_suite/run-1773381666/agent`
- 2026-03-13: intentionally abandoned the partial full-agent diagnostic `run-1773380439` and the partial combined 39-case diagnostic `run-1773381814`; both roots are non-authoritative and exist only as troubleshooting residue

## Iteration Update Protocol

This document is the persistent execution ledger for continued MiniWoB iteration. Each substantive iteration must update:

- current phase
- completed phases
- remaining phases
- latest benchmark snapshot by mode (`oracle`, `runtime`, `agent`, `candidate` when present)
- newly landed primitives, receipts, or planner/recipe coverage
- task families moved from `known_gap` to `passing`
- decisions made
- deviations from plan
- validation runs and known failures
- date-stamped implementation notes
- any still-running or intentionally abandoned benchmark rung so the next agent knows which results are authoritative and which are diagnostic only

Do not mark a phase complete until code, tests, docs, and benchmark evidence are all in place.

Authoritative update rules:

- treat serial suite runs as authoritative; overlapping or aborted runs are diagnostic only
- always record the exact run root for every benchmark number that matters
- reclassify failures after removing infra/startup noise; do not leave stale gap classes in the ledger
- when a low-level targeted slice closes, immediately define and run the next broader rung rather than pausing at the micro-benchmark
- when a combined slice is intentionally abandoned for iteration-speed reasons, record that explicitly here so no future agent mistakes a partial artifact tree for a benchmark result

## Benchmark Snapshot

Latest snapshot:

- `oracle`:
  - smoke: `8/8` passing
  - full discovered-catalog baseline: `23/130` at `crates/cli/target/computer_use_suite/run-1773347098/oracle`
  - post-pointer full recapture: `25/130` at `crates/cli/target/computer_use_suite/run-1773352560/oracle`
  - current authoritative full recapture: `63/130` at `crates/cli/target/computer_use_suite/run-1773368165/oracle`
- `runtime`:
  - smoke: `8/8` passing
  - full discovered-catalog baseline: `22/130` at `crates/cli/target/computer_use_suite/run-1773347098/runtime`
  - post-pointer full recapture: `23/130` at `crates/cli/target/computer_use_suite/run-1773352146/runtime`
  - current authoritative full recapture: `63/130` at `crates/cli/target/computer_use_suite/run-1773369088/runtime`
  - targeted PR8 realistic slice: `4/4` at `crates/cli/target/computer_use_suite/run-1773372368/runtime`
  - targeted `click-tab-2*` repair slice: `4/4` at `crates/cli/target/computer_use_suite/run-1773380215/runtime`
  - broader PR8 realistic regression slice: `32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
- `agent`:
  - smoke: `8/8` passing
  - first broad catalog slice: `18/28` at `crates/cli/target/computer_use_suite/run-1773347279/agent`
  - targeted click-tab/hover slice after the startup and recovery fixes: `4/5` at `crates/cli/target/computer_use_suite/run-1773371794/agent`
  - targeted PR8 realistic slice: `4/4` at `crates/cli/target/computer_use_suite/run-1773372670/agent`
  - targeted hover regression check: `0/1` at `crates/cli/target/computer_use_suite/run-1773372854/agent`, correctly classified as `missing_pointer_primitive`
  - targeted scroll repair slice: `1/1` at `crates/cli/target/computer_use_suite/run-1773379418/agent`
  - targeted residual planner slice: `3/3` at `crates/cli/target/computer_use_suite/run-1773379444/agent`
  - broader PR8 realistic regression slice: `32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`
  - targeted text-and-logic coverage-expansion slice: `7/7` at `crates/cli/target/computer_use_suite/run-1773381666/agent`
- `candidate`: not started

Artifact roots for the main measured checkpoints:

- `crates/cli/target/computer_use_suite/run-1773347279/agent`
- `crates/cli/target/computer_use_suite/run-1773350420/oracle`
- `crates/cli/target/computer_use_suite/run-1773350420/runtime`
- `crates/cli/target/computer_use_suite/run-1773352146/runtime`
- `crates/cli/target/computer_use_suite/run-1773352560/oracle`
- `crates/cli/target/computer_use_suite/run-1773368165/oracle`
- `crates/cli/target/computer_use_suite/run-1773369088/runtime`
- `crates/cli/target/computer_use_suite/run-1773371794/agent`
- `crates/cli/target/computer_use_suite/run-1773372368/runtime`
- `crates/cli/target/computer_use_suite/run-1773372670/agent`
- `crates/cli/target/computer_use_suite/run-1773372854/agent`
- `crates/cli/target/computer_use_suite/run-1773379418/agent`
- `crates/cli/target/computer_use_suite/run-1773379444/agent`
- `crates/cli/target/computer_use_suite/run-1773379509/agent`
- `crates/cli/target/computer_use_suite/run-1773380215/runtime`
- `crates/cli/target/computer_use_suite/run-1773380341/runtime`
- `crates/cli/target/computer_use_suite/run-1773381666/agent`

## Capability Gap Matrix

Latest measured matrix state on 2026-03-13:

- the authoritative full discovered-catalog pair is still `oracle 63/130` and `runtime 63/130`; that full-pair ledger has not yet been refreshed after the `click-tab-2*` repair and the latest agent coverage expansion
- the last full-pair open families therefore remain:
  - `planner_gap=51`
  - `missing_pointer_primitive=15`
  - `missing_keyboard_primitive=1`
- no live `observation_gap` is currently exposed by the newest targeted or broader realistic slices; the active frontier is planner/recipe breadth rather than observation fallback weakness

Closed tranche tasks with current measured evidence:

| Task / family | `oracle` | `runtime` | Primary gap class | Secondary tags | Current support state |
| --- | --- | --- | --- | --- | --- |
| `hover-shape` | passing | passing | n/a | n/a | `passing` |
| `drag-items` | passing | passing | n/a | n/a | `passing` |
| `highlight-text` | passing | passing | n/a | n/a | `passing` |
| `highlight-text-2` | passing | passing | n/a | n/a | `passing` |
| `copy-paste` | passing | passing | n/a | n/a | `passing` |
| `copy-paste-2` | passing | passing | n/a | n/a | `passing` |

PR8 closure movement:

- targeted realistic-mode selection/clipboard tasks are closed in both realistic lanes
- the broader realistic regression rung is now closed in both lanes:
  - `runtime 32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
  - `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`
- no selection, clipboard, or key-chord task remains open in the broader PR8 realistic slice

Agent coverage-expansion movement on 2026-03-13:

- `simple-arithmetic`, `simple-algebra`, `odd-or-even`, `find-word`, `read-table`, `read-table-2`, and `phone-book` now pass in `agent` at `crates/cli/target/computer_use_suite/run-1773381666/agent`
- that movement came from bridge-visible-text parsing plus generic typed form-entry and selector-driven actions; no MiniWoB-only product logic was added to the runtime or agent service layers
- the next unported runtime-covered agent families are still concentrated in forms/editor/social/email/visual/canvas cases rather than in low-level browser primitives

Broad-mode deltas from the current authoritative full pair:

- `oracle`-only pass: none
- `runtime`-only pass: none
- `agent` has now matched the 32-case broader PR8 realistic slice and added a separate `7/7` text-and-logic expansion slice, but an authoritative broader/full-catalog `agent` recapture is still pending

## Benchmark Escalation Ladder

Measured ladder as of 2026-03-13:

1. Full-catalog `oracle` baseline.
   Status: complete.
   Evidence: authoritative full discovered-catalog `oracle` baseline at `23/130` under `crates/cli/target/computer_use_suite/run-1773347098/oracle`, later improved to `63/130` under `crates/cli/target/computer_use_suite/run-1773368165/oracle`.
2. Broad/full-catalog `runtime` baseline with gap matrix.
   Status: complete.
   Evidence: authoritative full discovered-catalog `runtime` baseline at `22/130` under `crates/cli/target/computer_use_suite/run-1773347098/runtime`, later improved to `63/130` under `crates/cli/target/computer_use_suite/run-1773369088/runtime`.
3. Broad/full-catalog `agent` baseline.
   Status: complete.
   Evidence: first broad catalog `agent` slice captured at `18/28` under `crates/cli/target/computer_use_suite/run-1773347279/agent`.
4. Close the highest-yield primitive gaps.
   Status: complete.
   Evidence: pointer tranche landed with typed receipts/postconditions; `hover-shape` and `drag-items` pass in `oracle` and `runtime`.
5. Close the selection/keyboard/clipboard/focus tranche.
   Status: complete.
   Evidence:
   - targeted PR8 realistic slices closed at `runtime 4/4` and `agent 4/4`
   - broader realistic slices closed at `runtime 32/32` and `agent 32/32`
   - startup/readiness, zero-floor gating, hidden-tab recovery, selection range, clipboard, and key-chord work all landed with tests and artifacts
6. Observation/verification hardening.
   Status: pending only if a fresh broad/full recapture re-exposes an observation-led blocker.
   Current read: the newest realistic slices are not observation-limited; no new PR9 observation tranche has been opened.
7. Stable broad `runtime` and `agent` coverage.
   Status: in progress.
   Evidence so far:
   - `runtime 32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
   - `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`
   - `agent 7/7` text-and-logic expansion slice at `crates/cli/target/computer_use_suite/run-1773381666/agent`
   Next rung:
   - port the remaining runtime-covered `agent` families (`form-sequence*`, `login-user-popup`, `text-editor`, `guess-number`, `find-greatest`, `social-media*`, `stock-market`, `email-inbox`, `visual-addition`, `identify-shape`, `count-shape`, `count-sides`, `find-midpoint`)
   - rerun a larger authoritative `agent` slice once that next batch lands
   Exit criterion:
   - authoritative agent breadth extends beyond the old 32-case slice without surfacing new low-level primitive regressions
8. Benchmark-only full-catalog `candidate` lane.
   Status: pending.
   Exit criterion:
   - `candidate` exists as a clearly separated lane on the same real tool substrate and has its own typed reporting
9. Repeated-seed and repeated-run stability targets.
   Status: pending.
   Exit criterion:
   - broadened runtime/agent slices stop surfacing new low-level failures across repeated seeds/runs before candidate-lane work is treated as stable
10. Post-MiniWoB benchmark expansion.
    Status: pending.
    Exit criterion:
    - MiniWoB no longer surfaces the primary missing primitive, observation, or planner requirements, at which point a new external benchmark frontier is added here immediately

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

Continuation completion for this initiative should mean:

- the suite remains a stable local and CI benchmark for `oracle`, `runtime`, and `agent`
- broad MiniWoB coverage has been baselined and maintained in this document
- missing generic primitives for hover, drag, selection, key-chord, clipboard, and focus-heavy flows are exposed through real repo tool surfaces
- completion is gated by typed observations and postconditions rather than UI movement or final text alone
- `runtime` and `agent` improve coverage without MiniWoB-only shortcuts
- a separate `candidate` lane exists if parity work is pursued, and it stays cleanly separated from product-facing execution lanes

## Sources

- <https://miniwob.farama.org/index.html>
- <https://miniwob.farama.org/content/observation_space/>
- <https://miniwob.farama.org/content/action_space/>
- <https://miniwob.farama.org/content/reward/>
- <https://miniwob.farama.org/content/javascript_api/>
