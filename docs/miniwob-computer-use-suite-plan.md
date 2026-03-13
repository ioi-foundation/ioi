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

- PR11 runtime and agent coverage expansion reached the explicit MiniWoB exhaustion checkpoint for product-facing work on 2026-03-13. The runtime-covered agent family tranche now closes at `agent 25/25` under `crates/cli/target/computer_use_suite/run-1773396334/agent`.
- The broader PR8 realistic regression rung remains green in both lanes: `runtime 32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime` and `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`. PR7 and PR8 stay closed; no current artifact-backed regression justifies reopening low-level pointer, selection, clipboard, or focus work.
- Agent coverage had already moved beyond the old curated slice at `agent 7/7` under `crates/cli/target/computer_use_suite/run-1773381666/agent` for `simple-arithmetic`, `simple-algebra`, `odd-or-even`, `find-word`, `read-table`, `read-table-2`, and `phone-book`. The new authoritative `25/25` slice extends that breadth across forms, editors, social-media, inbox, visual, and canvas families that direct runtime already solved.
- `count-sides` exposed a real observation/policy gap in realistic agent mode and is now closed. Diagnostic evidence: `agent 0/1` at `crates/cli/target/computer_use_suite/run-1773395523/agent` with `browser__canvas_summary` blocked by browser intent scope. Closure evidence: `agent 1/1` at `crates/cli/target/computer_use_suite/run-1773395678/agent`, plus inclusion in the authoritative `agent 25/25` slice at `crates/cli/target/computer_use_suite/run-1773396334/agent`.
- `stock-market` exposed the last remaining runtime-covered agent recipe gap in the first broader recapture (`agent 24/25` at `crates/cli/target/computer_use_suite/run-1773395719/agent`) and is now closed via focus-before-wait sequencing. Targeted validation: `runtime 1/1` at `crates/cli/target/computer_use_suite/run-1773396230/runtime`, `agent 1/1` at `crates/cli/target/computer_use_suite/run-1773396302/agent`, and then the authoritative `agent 25/25` recapture at `crates/cli/target/computer_use_suite/run-1773396334/agent`.
- The latest authoritative full discovered-catalog pair is still `oracle 63/130` at `crates/cli/target/computer_use_suite/run-1773368165/oracle` and `runtime 63/130` at `crates/cli/target/computer_use_suite/run-1773369088/runtime`. Those full totals remain historically correct, but they are no longer the product-facing control metric once the runtime-covered family tranche has closed.
- `find-midpoint` remains the only named runtime-covered realistic non-pass on the current frontier, but current artifacts isolate it as benchmark-floor residue rather than a planner/runtime/browser gap: both realistic lanes top out at `raw_reward = 0.98333335` under `crates/cli/target/computer_use_suite/run-1773395042/{runtime,agent}` because the task expects a half-pixel midpoint. That residue moves to the benchmark-only `candidate` lane unless a non-MiniWoB product case later demands subpixel pointer primitives.
- The next external benchmark frontier is now defined as a deterministic BrowserGym/WorkArena/WebArena-style multi-page real-browser workflow slice. MiniWoB's remaining open space is now mostly survey-only recipe additions plus benchmark-floor residue, not the main source of product-relevant capability pressure.

Completed phases:

- PR1 complete: sibling `computer_use_suite` module tree, typed case/result models, task manifests, judge, harness, and test target landed under `crates/cli/tests`
- PR2 complete: Python MiniWoB bridge landed under `tools/miniwob` with deterministic seeded session lifecycle, local `file://` task materialization, state sync, and oracle-step support
- PR3 complete: direct `runtime` mode drives MiniWoB through repo browser/computer-use tools, captures artifacts, and passes the smoke slice
- PR4 complete: `agent` mode routes through `DesktopAgentService`, enforces local judging on reward plus kernel behavior, and passes the smoke slice
- PR5 complete: `core` and `stress` manifests are populated, aggregate JSONL/CSV/Markdown reporting is emitted, helper scripts exist for local and CI-oriented runs, and bridge/docs were updated
- PR6 complete: discovered full-catalog `oracle` and `runtime` baselines were captured, a first broad catalog `agent` slice was recorded, and the gap matrix/benchmark ledger now tracks support state plus primary/secondary capability gaps
- PR7 complete: real browser pointer primitives (`hover`, `pointer_move`, `mouse_down`, `mouse_up`, composed `drag`) landed with typed receipts/postconditions, targeted pointer tasks pass in `oracle` and `runtime`, and the broad benchmark moved materially after the tranche
- PR8 complete: selection-range support, modifier-aware key chords, clipboard flows, focus/startup hardening, duplicate-wait dedupe hardening, one-shot startup navigation for agent mode, zero-floor completion gating fixes, and the PR8 closure slices all landed with code, tests, docs, and broader realistic-mode validation
- PR11 product-facing runtime-covered breadth tranche complete: authoritative realistic slices now include `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`, `agent 7/7` at `crates/cli/target/computer_use_suite/run-1773381666/agent`, and `agent 25/25` at `crates/cli/target/computer_use_suite/run-1773396334/agent` without reopening low-level primitives

Remaining phases:

- PR9: observation hardening if a fresh broad/full recapture exposes a real observation-led family again
- PR10: recovery and verification hardening
- PR12: separate full-catalog `candidate` lane for residual MiniWoB survey-family parity plus `find-midpoint`
- post-MiniWoB external benchmark expansion using deterministic BrowserGym/WorkArena/WebArena-style workflows

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
- the next high-yield agent work should port runtime-covered catalog families before opening new survey-only recipes; the latest iteration followed that rule through the closed `agent 25/25` runtime-covered family slice
- non-mutating browser inspection helpers needed inside active browser tasks (`browser__snapshot`, `browser__canvas_summary`) must be callable under the browser interaction capability surface; blocking them creates false policy failures rather than meaningful product constraints
- realistic browser pointer coordinates must preserve floats, and text insertion should emit the DOM key events pages actually observe, so benchmark pressure lands on real browser behavior instead of artificial truncation artifacts
- `find-midpoint` should be classified from artifacts, not from the suite's generic fallback labels: the realistic residue is `missing_pointer_primitive` with `subpixel_click_precision` / `page_event_integer_quantization`, not a planner gap
- once the runtime-covered MiniWoB families are closed and the remaining open work is mostly harness recipes or benchmark-floor residue, MiniWoB stops being the product-facing benchmark frontier and further parity work should move to `candidate`

Deviations from original plan:

- the bridge exposes an additional `/health` probe and page-driven `/sync` endpoint to make sidecar startup and browser-state synchronization deterministic
- `cargo test` runs the suite from `crates/cli`, so baseline artifact roots emitted as `target/computer_use_suite/...` resolve under `crates/cli/target/computer_use_suite/...`
- realistic modes still avoid `browser__snapshot` as a primary action dependency on MiniWoB `file://` pages because Chromium AX snapshots can be unreliable there; bridge state and real browser primitives remain the authoritative action substrate
- PR8 started exactly where the benchmark isolated the next missing generic primitives: `highlight-text` (`selection_range`) and `copy-paste` (`clipboard`, `key_chord`)
- PR8 had to absorb two generic agent/runtime control-flow fixes that were not obvious from the original tranche definition but were required for truthful validation:
  - one-shot startup navigation in agent mode
  - zero-floor completion gating in both the outer agent loop and `next_action`
- the hover-only agent reruns briefly looked like PR8 regressions, but after removing the startup/zero-floor false positives they resolved back to the real remaining pointer issue: hover verification still reports `hovered=false` on `#highlight`
- the next post-PR8 movement came from agent-visible-text parsing, broader DOM export, selector-driven recipe expansion, and browser-inspect follow-up scope fixes rather than from opening another low-level primitive tranche
- the bridge now exports generic `dom_elements`, and the suite runtime consumes successful `browser__canvas_summary` kernel events to cache canvas observations without adding benchmark-native action shortcuts to realistic modes
- `stock-market` agent behavior now mirrors the existing direct runtime strategy of focusing the buy control first and then waiting for the threshold, rather than relying on a simplified wait/click variant
- `find-midpoint` remains in MiniWoB reporting but has been moved out of product-facing PR11 work and into the future benchmark-only `candidate` lane

Validation status:

- `cargo test -p ioi-services browser_interaction_scope_allows_pointer_followups -- --nocapture` passed on 2026-03-12 after extending browser interaction capability bindings for pointer follow-ups
- `cargo test -p ioi-cli --test computer_use_suite_e2e synthetic_kernel_events_do_not_count_as_executed_tools -- --nocapture` passed on 2026-03-12 after filtering synthetic `system::max_steps_reached` events from kernel tool accounting
- `cargo test -p ioi-services browser_wait_is_allowed_to_repeat_on_adjacent_steps -- --nocapture` passed on 2026-03-12 after exempting `browser__wait` from adjacent non-command replay blocking
- `cargo test -p ioi-services browser_interaction_scope_allows_ -- --nocapture` passed on 2026-03-13 after allowing non-mutating browser inspection follow-ups inside active browser interaction scope
- `cargo test -p ioi-services test_normalize_synthetic_click -- --nocapture` passed on 2026-03-13 after preserving float pointer coordinates through tool normalization
- `cargo test -p ioi-cli --test computer_use_suite_e2e 'computer_use_suite::harness::tests::find_midpoint_' -- --nocapture` passed on 2026-03-13 after updating midpoint geometry expectations for float coordinates
- `cargo test -p ioi-cli --test computer_use_suite_e2e 'computer_use_suite::harness::tests::count_sides_' -- --nocapture` passed on 2026-03-13 after landing canvas-summary caching in `MiniwobAgentRuntime`
- `cargo test -p ioi-cli --test computer_use_suite_e2e 'computer_use_suite::harness::tests::stock_market_' -- --nocapture` passed on 2026-03-13 after mirroring the direct runtime focus-before-wait sequence in the agent recipe
- `cargo test -p ioi-cli --test computer_use_suite_e2e 'computer_use_suite::harness::tests::' -- --nocapture` passed on 2026-03-13 (`56 passed`) after the count-sides, stock-market, and midpoint updates
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with targeted PR8 realistic-mode validation: `runtime 4/4`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773372368/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with targeted PR8 realistic-mode validation: `agent 4/4`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773372670/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_choose_list,miniwob_catalog_click_button,miniwob_catalog_click_button_sequence,miniwob_catalog_click_checkboxes,miniwob_catalog_click_checkboxes_large,miniwob_catalog_click_checkboxes_soft,miniwob_catalog_click_checkboxes_transfer,miniwob_catalog_click_collapsible,miniwob_catalog_click_collapsible_2,miniwob_catalog_click_collapsible_2_nodelay,miniwob_catalog_click_collapsible_nodelay,miniwob_catalog_click_link,miniwob_catalog_click_option,miniwob_catalog_click_tab,miniwob_catalog_click_tab_2,miniwob_catalog_click_tab_2_easy,miniwob_catalog_click_tab_2_hard,miniwob_catalog_click_tab_2_medium,miniwob_catalog_enter_password,miniwob_catalog_enter_text,miniwob_catalog_enter_text_2,miniwob_catalog_focus_text,miniwob_catalog_focus_text_2,miniwob_catalog_login_user,miniwob_catalog_scroll_text_2,miniwob_catalog_search_engine,miniwob_catalog_use_autocomplete,miniwob_catalog_use_autocomplete_nodelay,miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with a broader realistic agent slice: `agent 32/32`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773379509/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_choose_list,miniwob_catalog_click_button,miniwob_catalog_click_button_sequence,miniwob_catalog_click_checkboxes,miniwob_catalog_click_checkboxes_large,miniwob_catalog_click_checkboxes_soft,miniwob_catalog_click_checkboxes_transfer,miniwob_catalog_click_collapsible,miniwob_catalog_click_collapsible_2,miniwob_catalog_click_collapsible_2_nodelay,miniwob_catalog_click_collapsible_nodelay,miniwob_catalog_click_link,miniwob_catalog_click_option,miniwob_catalog_click_tab,miniwob_catalog_click_tab_2,miniwob_catalog_click_tab_2_easy,miniwob_catalog_click_tab_2_hard,miniwob_catalog_click_tab_2_medium,miniwob_catalog_enter_password,miniwob_catalog_enter_text,miniwob_catalog_enter_text_2,miniwob_catalog_focus_text,miniwob_catalog_focus_text_2,miniwob_catalog_login_user,miniwob_catalog_scroll_text_2,miniwob_catalog_search_engine,miniwob_catalog_use_autocomplete,miniwob_catalog_use_autocomplete_nodelay,miniwob_catalog_highlight_text,miniwob_catalog_highlight_text_2,miniwob_catalog_copy_paste,miniwob_catalog_copy_paste_2 COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with a broader direct-mode regression slice: `runtime 32/32`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_simple_arithmetic,miniwob_catalog_simple_algebra,miniwob_catalog_odd_or_even,miniwob_catalog_find_word,miniwob_catalog_read_table,miniwob_catalog_read_table_2,miniwob_catalog_phone_book COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with targeted agent coverage-expansion validation: `agent 7/7`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773381666/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_find_midpoint COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` and `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_find_midpoint COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` remained `0/1` on 2026-03-13 under `crates/cli/target/computer_use_suite/run-1773395042/{runtime,agent}` even after float-coordinate and midpoint-geometry fixes; bridge artifacts show `raw_reward = 0.98333335`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_count_sides COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` first failed diagnostically on 2026-03-13 with `agent 0/1` at `crates/cli/target/computer_use_suite/run-1773395523/agent` (`PolicyBlocked` on `browser__canvas_summary`), then passed at `agent 1/1` under `crates/cli/target/computer_use_suite/run-1773395678/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_form_sequence,miniwob_catalog_form_sequence_2,miniwob_catalog_form_sequence_3,miniwob_catalog_login_user_popup,miniwob_catalog_text_editor,miniwob_catalog_guess_number,miniwob_catalog_find_greatest,miniwob_catalog_social_media,miniwob_catalog_social_media_all,miniwob_catalog_social_media_some,miniwob_catalog_stock_market,miniwob_catalog_email_inbox,miniwob_catalog_email_inbox_delete,miniwob_catalog_email_inbox_forward,miniwob_catalog_email_inbox_forward_nl,miniwob_catalog_email_inbox_forward_nl_turk,miniwob_catalog_email_inbox_important,miniwob_catalog_email_inbox_nl_turk,miniwob_catalog_email_inbox_noscroll,miniwob_catalog_email_inbox_reply,miniwob_catalog_email_inbox_star_reply,miniwob_catalog_visual_addition,miniwob_catalog_identify_shape,miniwob_catalog_count_shape,miniwob_catalog_count_sides COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` first completed diagnostically at `agent 24/25` under `crates/cli/target/computer_use_suite/run-1773395719/agent`, isolating `stock-market` as the last remaining gap in the batch
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_stock_market COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with `runtime 1/1`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773396230/runtime`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_stock_market COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-13 with `agent 1/1`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773396302/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_form_sequence,miniwob_catalog_form_sequence_2,miniwob_catalog_form_sequence_3,miniwob_catalog_login_user_popup,miniwob_catalog_text_editor,miniwob_catalog_guess_number,miniwob_catalog_find_greatest,miniwob_catalog_social_media,miniwob_catalog_social_media_all,miniwob_catalog_social_media_some,miniwob_catalog_stock_market,miniwob_catalog_email_inbox,miniwob_catalog_email_inbox_delete,miniwob_catalog_email_inbox_forward,miniwob_catalog_email_inbox_forward_nl,miniwob_catalog_email_inbox_forward_nl_turk,miniwob_catalog_email_inbox_important,miniwob_catalog_email_inbox_nl_turk,miniwob_catalog_email_inbox_noscroll,miniwob_catalog_email_inbox_reply,miniwob_catalog_email_inbox_star_reply,miniwob_catalog_visual_addition,miniwob_catalog_identify_shape,miniwob_catalog_count_shape,miniwob_catalog_count_sides COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` then completed authoritatively on 2026-03-13 with `agent 25/25`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773396334/agent`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=oracle COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with the current authoritative full discovered-catalog oracle snapshot: `63/130`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773368165/oracle`
- `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-src-ioi COMPUTER_USE_SUITE_MODE=runtime COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0 COMPUTER_USE_SUITE_HEADLESS=1 COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS=1 tools/miniwob/run_suite.sh` completed on 2026-03-12 with the current authoritative full discovered-catalog runtime snapshot: `63/130`, artifacts rooted at `crates/cli/target/computer_use_suite/run-1773369088/runtime`

Known failures / unrelated issues:

- repository-wide compiler/test warnings remain noisy but are pre-existing and unrelated to MiniWoB progress
- the authoritative full-catalog `runtime`/`oracle` pair is still the older `63/130` snapshot; no fresh full runtime or full agent recapture has been taken after the newer realistic slices because those totals are no longer the product-facing control metric
- there is still no authoritative full-catalog `agent` total beyond the original broad baseline; the attempted all-catalog agent diagnostic at `crates/cli/target/computer_use_suite/run-1773380439/agent` was intentionally abandoned because it is too slow to be a useful iteration loop in its current form
- the aborted combined 39-case agent diagnostic at `crates/cli/target/computer_use_suite/run-1773381814/agent` is non-authoritative and should not be used for status; rely on the closed `agent 32/32`, `agent 7/7`, and `agent 25/25` slices instead
- `find-midpoint` remains a diagnostic realistic-mode non-pass at `crates/cli/target/computer_use_suite/run-1773395042/{runtime,agent}`. The artifact-backed primary gap is `missing_pointer_primitive`, with secondary tags `subpixel_click_precision` and `page_event_integer_quantization`; do not reopen PR7/PR8 wholesale for this MiniWoB-only residue
- remaining MiniWoB open space beyond the closed runtime-covered family tranche is now dominated by survey-only recipe additions over already-covered primitives; that work belongs in the benchmark-only `candidate` lane rather than in product-facing PR11
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
- 2026-03-13: the bridge now exports generic `dom_elements`, and `MiniwobAgentRuntime` now consumes successful `browser__canvas_summary` kernel events to cache shape-side estimates; this closed the realistic agent `count-sides` gap after allowing browser-inspect follow-ups under browser interaction scope
- 2026-03-13: preserved float `x/y` for `browser__synthetic_click` and `browser__move_mouse` and emitted synthetic DOM `keyup` after text insertion; these changes isolated `find-midpoint` to a half-pixel benchmark floor instead of a recipe math bug or coordinate truncation bug
- 2026-03-13: first broader recapture of the runtime-covered family tranche landed at `agent 24/25` under `crates/cli/target/computer_use_suite/run-1773395719/agent`, isolating `stock-market` as the last remaining gap in the batch
- 2026-03-13: updated the `stock-market` agent recipe to focus `#buy` via `Tab`, wait until the observed price crosses the query threshold, and then submit with `Enter`; targeted live reruns passed at `runtime 1/1` under `crates/cli/target/computer_use_suite/run-1773396230/runtime` and `agent 1/1` under `crates/cli/target/computer_use_suite/run-1773396302/agent`
- 2026-03-13: clean serial recapture of the runtime-covered family tranche closed at `agent 25/25` under `crates/cli/target/computer_use_suite/run-1773396334/agent`; this is now the authoritative PR11 breadth checkpoint
- 2026-03-13: MiniWoB reached the rung-7 product-facing exhaustion checkpoint. Remaining MiniWoB parity work (`find-midpoint` plus survey-only families) moves to the future benchmark-only `candidate` lane, and the next external frontier is now defined as deterministic BrowserGym/WorkArena/WebArena-style multi-page workflows

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
  - diagnostic `find-midpoint` ceiling after float-coordinate and geometry fixes: `0/1` at `crates/cli/target/computer_use_suite/run-1773395042/runtime` with `raw_reward = 0.98333335`
  - targeted `stock-market` validation after the agent-side diagnosis: `1/1` at `crates/cli/target/computer_use_suite/run-1773396230/runtime`
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
  - diagnostic `find-midpoint` ceiling after float-coordinate and geometry fixes: `0/1` at `crates/cli/target/computer_use_suite/run-1773395042/agent` with `raw_reward = 0.98333335`
  - diagnostic `count-sides` policy failure before browser-inspect scope expansion: `0/1` at `crates/cli/target/computer_use_suite/run-1773395523/agent`
  - targeted `count-sides` closure slice: `1/1` at `crates/cli/target/computer_use_suite/run-1773395678/agent`
  - diagnostic first broader recapture of the runtime-covered family tranche: `24/25` at `crates/cli/target/computer_use_suite/run-1773395719/agent`
  - targeted `stock-market` closure slice: `1/1` at `crates/cli/target/computer_use_suite/run-1773396302/agent`
  - authoritative runtime-covered family breadth slice: `25/25` at `crates/cli/target/computer_use_suite/run-1773396334/agent`
- `candidate`: not started; designated for residual MiniWoB parity (`find-midpoint` plus survey-only families) rather than product-facing PR11 work

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
- `crates/cli/target/computer_use_suite/run-1773395042/runtime`
- `crates/cli/target/computer_use_suite/run-1773395042/agent`
- `crates/cli/target/computer_use_suite/run-1773395523/agent`
- `crates/cli/target/computer_use_suite/run-1773395678/agent`
- `crates/cli/target/computer_use_suite/run-1773395719/agent`
- `crates/cli/target/computer_use_suite/run-1773396230/runtime`
- `crates/cli/target/computer_use_suite/run-1773396302/agent`
- `crates/cli/target/computer_use_suite/run-1773396334/agent`

## Capability Gap Matrix

Latest measured matrix state on 2026-03-13:

- the authoritative full discovered-catalog pair is still `oracle 63/130` and `runtime 63/130`; that full-pair ledger has not been refreshed after the newer realistic slices, and it is now secondary to the closed runtime-covered family tranche
- the last full-pair open families therefore still reflect the older full-pair ledger:
  - `planner_gap=51`
  - `missing_pointer_primitive=15`
  - `missing_keyboard_primitive=1`
- the current high-yield realistic frontier is no longer exposing a live observation or recovery blocker. `count-sides` closed the last product-facing observation/policy issue in this batch, and `stock-market` closed the last planner/recipe hole in the runtime-covered family tranche
- the only named realistic non-pass still tracked on this frontier is `find-midpoint`, and its current artifact-backed classification is `missing_pointer_primitive` with secondary tags `subpixel_click_precision` and `page_event_integer_quantization`; it should not be counted as a planner gap

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
- the next runtime-covered agent families were then ported and closed in the authoritative `agent 25/25` slice at `crates/cli/target/computer_use_suite/run-1773396334/agent`: `form-sequence*`, `login-user-popup`, `text-editor`, `guess-number`, `find-greatest`, `social-media*`, `stock-market`, `email-inbox*`, `visual-addition`, `identify-shape`, `count-shape`, and `count-sides`
- the reusable capability patterns that moved in this batch were:
  - browser-inspect follow-ups under browser interaction scope for observation-assisted tasks (`count-sides`)
  - kernel-event observation caching for `browser__canvas_summary`
  - float-preserving pointer coordinates and DOM keyup parity
  - focus-before-wait sequencing for event-driven browser tasks (`stock-market`)
- after the `agent 25/25` closure slice, the remaining MiniWoB delta is mostly survey-only recipe parity plus the benchmark-floor `find-midpoint` residue, not product-relevant primitive or planner expansion

Broad-mode deltas from the current authoritative full pair:

- `oracle`-only pass: none
- `runtime`-only pass: none
- `agent` has now matched the 32-case broader PR8 realistic slice, added the separate `7/7` text-and-logic expansion slice, and closed an authoritative `25/25` runtime-covered family slice at `crates/cli/target/computer_use_suite/run-1773396334/agent`
- MiniWoB exhaustion assessment: the closed `25/25` runtime-covered slice means the remaining product-facing MiniWoB movement is exhausted. Residual parity work belongs in `candidate`, and the next product-facing benchmark pressure should come from the new multi-page BrowserGym/WorkArena/WebArena-style frontier

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
   Status: closed for current MiniWoB product-facing work.
   Evidence:
   - `count-sides` first exposed a real observation/policy blocker at `crates/cli/target/computer_use_suite/run-1773395523/agent`
   - browser-inspect follow-up scope plus canvas-summary event observation closed that blocker at `crates/cli/target/computer_use_suite/run-1773395678/agent` and inside the authoritative `agent 25/25` slice at `crates/cli/target/computer_use_suite/run-1773396334/agent`
7. Stable broad `runtime` and `agent` coverage.
   Status: complete for product-facing MiniWoB work; explicit exhaustion checkpoint reached.
   Evidence so far:
   - `runtime 32/32` at `crates/cli/target/computer_use_suite/run-1773380341/runtime`
   - `agent 32/32` at `crates/cli/target/computer_use_suite/run-1773379509/agent`
   - `agent 7/7` text-and-logic expansion slice at `crates/cli/target/computer_use_suite/run-1773381666/agent`
   - `agent 25/25` runtime-covered family breadth slice at `crates/cli/target/computer_use_suite/run-1773396334/agent`
   Exhaustion checkpoint:
   - this batch still closed real reusable capability patterns: browser-inspect follow-up scope, canvas-summary observation caching, float-preserving pointer coordinates, DOM keyup parity, and focus-before-wait sequencing
   - after those closures, the only named realistic miss left on the runtime-covered frontier is `find-midpoint`, whose latest artifacts at `crates/cli/target/computer_use_suite/run-1773395042/{runtime,agent}` cap out at `raw_reward = 0.98333335` because the task expects a half-pixel midpoint; treat that as benchmark-only `candidate` residue
   - the next MiniWoB batches are now mostly suite-harness recipe additions on top of already-covered primitives, which no longer represents product-facing progress
   Exit criterion:
   - authoritative agent breadth extends beyond the old 32-case slice without surfacing new low-level primitive regressions
   Result:
   - satisfied; product-facing MiniWoB work moves to rung 8 and rung 10
8. Benchmark-only full-catalog `candidate` lane.
   Status: pending implementation, now designated as the only valid lane for residual MiniWoB parity work.
   Scope:
   - residual MiniWoB survey families
   - `find-midpoint` half-pixel precision residue
   Guardrail:
   - no product-routing, capability, or benchmark-conditioned heuristics may be added while chasing this lane
9. Repeated-seed and repeated-run stability targets.
   Status: pending.
   Exit criterion:
   - broadened runtime/agent slices stop surfacing new low-level failures across repeated seeds/runs before candidate-lane work is treated as stable
10. Post-MiniWoB benchmark expansion.
    Status: defined and ready for follow-on implementation.
    Next external frontier:
    - deterministic BrowserGym/WorkArena/WebArena-style multi-page real-browser workflow slices
    - prioritize tasks that force navigation, persistent state, verification, and recovery across realistic pages rather than single-page microworld recipes
    Exit criterion:
    - a new benchmark harness exists in the repo plan and begins replacing MiniWoB as the main product-facing browser/computer-use forcing function

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
