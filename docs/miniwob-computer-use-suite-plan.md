# Browser / Computer-Use Discovery Plan

This file is the single authoritative backlog, status ledger, benchmark snapshot,
and living roadmap for browser/computer-use discovery. Historical MiniWoB and
local workflow results remain recorded here as regression and reproduction
baselines; active discovery is live-inference browser-first work.

- primary discovery lane: live inference on browser-first external benchmarks
- secondary reproduction lane: deterministic local reproductions for reusable gaps
- regression lane: MiniWoB plus local workflow fixtures

## Status

Current phase:

- Active frontier: prove and use real live inference on the repo's existing browser
  / computer-use stack, then push that stack against BrowserGym-style browser-first
  benchmarks.
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
- Live inference is now proven on the repo's real browser/computer-use path with
  `HttpInferenceRuntime`, `DesktopAgentService`, and `BrowserDriver` via the
  authoritative local browser smoke artifacts at
  `crates/cli/target/browser_live_runtime/run-1773431386` and
  `run-1773433420`.
- A smallest-viable BrowserGym-style WorkArena adapter surface now exists via
  `crates/cli/tests/workarena_live_e2e.rs` and
  `tools/browsergym/workarena_cdp_bridge.py`, but external bring-up is still
  blocked by repo-external Python dependencies and credentials.
- The local browser cognition path now downshifts to a browser-semantic prompt
  shape when visual evidence is placeholder-only, which removed the prior
  `gpt-4o` refusal on this smoke and yielded a clean `agent__complete` under
  `run-1773433420`.

Immediate goals:

1. Keep the live-inference browser proof path green on the repo-real
   `DesktopAgentService` / `BrowserDriver` stack and carry the current prompt
   shaping into the first browser-first external slice.
2. Convert the landed WorkArena adapter from typed preflight to an actual external
   browser-first live slice as soon as repo-external blockers are removed.
3. Backfill deterministic local reproduction only if a live artifact proves the
   remaining gap is reusable enough to justify it.

Exit criteria for the current phase:

- one authoritative artifact-backed run proving real provider-backed inference in a
  browser/computer-use benchmark flow
- one authoritative browser-first external smoke slice with typed success/failure
  classification
- the first live-discovered product gap either fixed or explicitly classified as a
  true repo-external blocker
- the next frontier after browser-first discovery clearly defined in this document

## Validation status

Retained regression and reproduction baselines:

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

- Authoritative local live browser proof recorded:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773431386`
  - Typed outcome: `dom_contains_done=true`
  - Classification: authoritative live browser smoke, not external benchmark yet
- Authoritative local live browser proof rerun after prompt-shape hardening:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773433420`
  - Typed outcome: `dom_contains_done=true`, clean `agent__complete`
  - Classification: authoritative live browser smoke and authoritative proof that
    the prior `gpt-4o` refusal no longer reproduces on this local slice
- Authoritative local live browser proof rerun on the prior `gpt-4o-mini` lane:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773433583`
  - Typed outcome: `dom_contains_done=true`, final agent status `Completed(None)`
    via `system::max_steps_reached`
  - Classification: authoritative capability proof plus a narrowed remaining
    `verification_gap`
- Diagnostic live browser runs that informed the shared fixes:
  - `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini ...` failed diagnostically under
    `crates/cli/target/browser_live_runtime/run-1773430382`,
    `run-1773430679`, `run-1773430842`, and `run-1773431173` while narrowing:
    page-leaving recovery drift (`recovery_gap`), then semantic observation
    persistence / tool-label loss (`observation_gap`), then residual planner
    misuse of duplicate snapshots (`planner_gap`).
  - Historical note:
    `cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
    with default-selected `gpt-4o` previously failed diagnostically under
    `crates/cli/target/browser_live_runtime/run-1773430304` with refusal on the
    browser cognition prompt. That failure is now corrected by the prompt-shape
    hardening recorded below.
- WorkArena adapter preflight validation recorded:
  - Command:
    `cargo test -p ioi-cli --test workarena_live_e2e workarena_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact`
  - Result: passed as typed diagnostic preflight
  - Classification: adapter bring-up succeeded, external execution still blocked
- Shared-fix targeted tests recorded:
  - `cargo test -p ioi-services --lib cognition::tests -- --nocapture`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::intent_resolver::tests::scope_policy::ui_interaction_scope_allows_browser_safe_followups' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::tools::discovery::tests::visual_foreground_browser_window_exposes_browser_followups_for_ui_interaction' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::deterministic_recovery_does_not_replay_browser_snapshot_after_duplicate_no_effect' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::duplicate_browser_snapshot_incident_forbids_navigation_remedies' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::deterministic_recovery_prefers_browser_snapshot_for_browser_target_not_found' -- --exact`
  - `cargo test -p ioi-services --lib browser_observation_context_ -- --nocapture`
  - Result: all passed

Required first validations for the new plan:

1. Preserve the existing proof that the active browser path is using a real
   provider-backed inference runtime rather than `MiniwobAgentRuntime`,
   `MockInferenceRuntime`, or the placeholder `StandardInferenceRuntime`.
2. Preserve the existing proof that the live path is the repo's real
   `DesktopAgentService` plus `BrowserDriver` stack.
3. Upgrade from the authoritative local live browser smoke to an authoritative
   external browser-first slice once the WorkArena bring-up blockers are removed.

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
- WorkArena external execution is currently blocked outside the repo by missing or
  unavailable `playwright`, missing or unusable `browsergym-workarena`, missing
  `INSTANCE_XOR_SEED`, and unavailable ServiceNow / Hugging Face access.
- The earlier `gpt-4o` cognition refusal under
  `crates/cli/target/browser_live_runtime/run-1773430304` is now a historical
  diagnostic, not a current blocker; `run-1773433420` passed after prompt-shape
  hardening.
- The post-success terminalization issue is now narrowed but still live:
  `gpt-4o` terminated cleanly in `run-1773433420`, while `gpt-4o-mini`
  reproduced `system::max_steps_reached` after typed success in
  `run-1773433583`. Keep class: `verification_gap`.
- Repo-wide warnings and unrelated dirty-worktree changes may still exist and
  should not be confused with live benchmark capability signals.
- `cargo-component` is not installed in the current environment, so the
  `mock-verifier` test component build step is skipped during browser live test
  setup. This did not block the live smoke runs recorded here.

## Date-stamped implementation notes

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
- 2026-03-13: Compressed repeated retrospective framing in this file so fresh
  agents land on the active frontier quickly. Baseline artifacts remain preserved
  in `Benchmark Snapshot` and `Validation status`.
- 2026-03-13: Added a real live browser smoke harness in
  `crates/cli/tests/browser_live_runtime_e2e.rs` backed by
  `HttpInferenceRuntime`, repo-real `DesktopAgentService`, repo-real
  `BrowserDriver`, and artifact emission under
  `crates/cli/target/browser_live_runtime/run-*`. Added
  `inference-calls.json` capture via `crates/cli/tests/live_inference_support.rs`
  so prompt/tool-call sequences are now typed artifacts rather than inferred from
  logs.
- 2026-03-13: Landed the smallest viable WorkArena adapter surfaces in
  `crates/cli/tests/workarena_live_e2e.rs` and
  `tools/browsergym/workarena_cdp_bridge.py`. The adapter is live-inference-ready
  on repo surfaces, but the actual external benchmark run is still blocked by
  repo-external dependencies and credentials.
- 2026-03-13: Fixed shared browser-safe capability exposure so browser follow-up
  tools remain available inside the existing scope policy and discovery surfaces.
  Targeted tests passed in
  `agentic::desktop::service::step::intent_resolver::tests::scope_policy::ui_interaction_scope_allows_browser_safe_followups`
  and
  `agentic::desktop::tools::discovery::tests::visual_foreground_browser_window_exposes_browser_followups_for_ui_interaction`.
- 2026-03-13: Fixed a shared `recovery_gap` where duplicate browser observation
  incidents could select page-leaving remedies such as `browser__navigate`.
  Recovery now forbids page-leaving remedies for duplicate `browser__snapshot`
  `NoEffectAfterAction` incidents and keeps remediation on-page. Targeted tests
  passed in incident recovery.
- 2026-03-13: Fixed a shared `observation_gap` on the live browser path by:
  - correcting cognition prompt section labeling
  - preserving the most recent semantic `browser__snapshot` evidence outside the
    `MAX_PROMPT_HISTORY` truncation window
  - tagging successful `browser__snapshot` tool history with the tool name so the
    model can recognize reusable browser evidence
  - preferring semantic snapshot payloads over later duplicate-snapshot error text
  Targeted tests passed under
  `agentic::desktop::service::step::cognition::history::tests::browser_observation_context_*`.
- 2026-03-13: Diagnostic run progression on `gpt-4o-mini`:
  - `run-1773430382`: semantic snapshot found `btn_mark_complete`, but the agent
    repeated `browser__snapshot` and recovery could drift off-page. Classes:
    `planner_gap` plus `recovery_gap`.
  - `run-1773430679`: page-leaving drift was removed, but the agent still chose
    low-value recovery actions instead of consuming the snapshot. Class:
    `planner_gap`.
  - `run-1773430842` and `run-1773431173`: prompt cleanup alone was insufficient;
    observation context still degraded because semantic snapshot evidence was not
    preserved or clearly labeled. Class: `observation_gap`.
  - `run-1773431386`: authoritative pass. The live model chose
    `browser__click_element { id: \"btn_mark_complete\" }` and the typed browser
    postcondition succeeded with `dom_contains_done=true`.
- 2026-03-13: Hardened the browser cognition prompt shape against local live
  refusal surfaces by:
  - suppressing visual-action framing when the attached screenshot is only a
    placeholder-sized image
  - downshifting browser steps to browser-semantic wording when browser tools are
    already available
  - removing anti-refusal wording from the kernel prompt
  - trimming browser-step tool and operating-rule surfaces to the browser-relevant
    subset
  Targeted unit coverage passed under
  `cargo test -p ioi-services --lib cognition::tests -- --nocapture`.
- 2026-03-13: `gpt-4o` no longer reproduces the earlier browser cognition refusal.
  Authoritative rerun `run-1773433420` selected `browser__snapshot`, then
  `browser__click_element { id: \"btn_mark_complete\" }`, then verified `done`
  and terminated cleanly with `agent__complete`.
- 2026-03-13: The `verification_gap` remains narrowed but unresolved after prompt
  hardening. Authoritative `gpt-4o-mini` rerun `run-1773433583` still achieved
  `dom_contains_done=true`, but exhausted steps via `system::max_steps_reached`
  instead of cleanly finalizing.

## Benchmark Snapshot

Active discovery benchmarks:

| Benchmark lane | Status | Authoritative result | Artifact root | Notes |
| --- | --- | --- | --- | --- |
| Live browser path proof / local browser smoke | authoritative local pass | `3/3 passed`; `gpt-4o` now cleanly completes, `gpt-4o-mini` still shows post-success terminalization drift | `crates/cli/target/browser_live_runtime/run-1773431386`, `crates/cli/target/browser_live_runtime/run-1773433420`, `crates/cli/target/browser_live_runtime/run-1773433583` | real `HttpInferenceRuntime` + repo-real browser/computer-use stack; local `gpt-4o` refusal is closed, but `verification_gap` remains on the `gpt-4o-mini` lane |
| Live browser-first external benchmark | adapter landed, external slice blocked | none yet | `crates/cli/tests/workarena_live_e2e.rs`, `tools/browsergym/workarena_cdp_bridge.py` | WorkArena preflight is typed and passing, but actual external run is repo-external-blocked |
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

The matrix below tracks which gap classes are currently product-active under the
live browser-first workflow.

| Gap class | Current live-discovery status | Local deterministic status | Current handling |
| --- | --- | --- | --- |
| `missing_pointer_primitive` | not yet re-evaluated | dormant baseline | reopen only if live browser-first failures require it |
| `missing_selection_primitive` | not yet re-evaluated | dormant baseline | keep MiniWoB coverage; do not reopen proactively |
| `missing_keyboard_primitive` | not yet re-evaluated | dormant baseline | reopen only on live evidence |
| `missing_clipboard_primitive` | not yet re-evaluated | dormant baseline | reopen only on live evidence |
| `observation_gap` | partially closed on live browser path | partially closed in local baselines | semantic snapshot evidence now survives incident chatter and enabled the authoritative semantic click |
| `verification_gap` | active but narrowed | partially closed in local baselines | `run-1773433420` terminated cleanly with `agent__complete`, but `run-1773433583` still hit `system::max_steps_reached` after typed success |
| `recovery_gap` | partially closed on live browser path | partially closed in local baselines | duplicate snapshot incidents no longer choose page-leaving browser remedies |
| `planner_gap` | narrowed / partially closed | several prior labels corrected away in local baselines | local live smoke now converts semantic snapshot evidence into `browser__click_element`; keep class open for harder slices |
| `infra_or_bridge_gap` | active non-product blocker class | known from prior local diagnostics | current active blockers are WorkArena external dependency / credential constraints; the local `gpt-4o` refusal is corrected |

Interpretation rules:

- "not yet re-evaluated" means the class is not currently active evidence, not that
  it is solved forever.
- "dormant baseline" means the repo has prior deterministic coverage, but that
  coverage does not prove the class is closed under live inference.
- Every live failure must be narrowed to the smallest honest class before it can be
  used to justify tooling work or deterministic reproduction work.

## Benchmark Escalation Ladder

Active escalation is tracked here. Historical deterministic ladder results remain
recorded in `Benchmark Snapshot` as baselines.

1. Live inference plumbing proof
   Status: closed.
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
   Recorded evidence:
   - Command:
     `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
   - Artifact root:
     `crates/cli/target/browser_live_runtime/run-1773431386`
   - Outcome:
     authoritative local live browser pass on `HttpInferenceRuntime`

2. Browser-first adapter bring-up
   Status: in progress; repo-external blocker on actual external execution.
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
   Recorded evidence:
   - Command:
     `cargo test -p ioi-cli --test workarena_live_e2e workarena_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact`
   - Outcome:
     typed preflight passed; actual external run still blocked by missing
     dependencies / credentials outside the repo

3. Browser-first live smoke slice
   Status: partially complete.
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
   Recorded evidence:
   - Diagnostic failures:
     `crates/cli/target/browser_live_runtime/run-1773430304`,
     `run-1773430382`, `run-1773430679`, `run-1773430842`,
     `run-1773431173`
   - Authoritative pass:
     `crates/cli/target/browser_live_runtime/run-1773431386`,
     `run-1773433420`, `run-1773433583`
   - Current interpretation:
     the local live browser slice now passes authoritatively on both `gpt-4o-mini`
     and `gpt-4o`; the local refusal issue is closed, while the remaining shared
     gap is a narrower post-success terminalization issue on `gpt-4o-mini`

4. Shared browser-first gap closure
   Status: in progress.
   Objective:
   - close the first live-discovered reusable browser/computer-use gap using shared
     tooling/runtime/observation/recovery improvements
   Requirements:
   - fix the product issue in shared surfaces, not in benchmark-local routing
   - rerun the failing task and then a broader slice
   Exit criteria:
   - authoritative rerun passes and the broader slice does not regress
   Progress:
   - closed / partially closed:
     duplicate snapshot page-leaving recovery drift and semantic browser snapshot
     evidence loss and local `gpt-4o` refusal on placeholder-visual browser
     prompts
   - next read:
     close the narrowed `verification_gap` on the local browser path, then carry
     the hardened browser prompt shape into the first external slice

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
   Status: pending; not yet exhausted.
   Objective:
   - determine whether browser-first live discovery is still yielding product
     signal
   Exit criteria:
   - either continue browser-first escalation, or define the next frontier as
     cross-app OSWorld / OSWorld-Verified
   Current read:
   - browser-first discovery is still yielding product-relevant signal because the
     remaining local gap is now narrow and model-sensitive (`verification_gap` on
     `gpt-4o-mini`), after which the next unresolved frontier is external browser
     benchmark bring-up

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
4. When a live run passes the typed browser postcondition but does not terminate
   cleanly, record the run as authoritative for capability proof while separately
   classifying the remaining issue as `verification_gap` with the corrected gap
   classification recorded explicitly.
5. Do not claim success from motion, screenshots, or logs alone. Require typed
   receipts, typed observations, or typed postconditions.
6. If a live run discovers a reusable gap, prefer a shared fix in runtime,
   observation, verification, recovery, or bridge surfaces before adding any
   deterministic reproduction.
7. Add deterministic `computer_use_suite` coverage only after a live failure proves
   the gap is real and reusable.
8. When a rung appears green, rerun the exact failing slice first, then run a
   broader slice before calling the rung stable.
9. If a failure is due to benchmark checkout, licensing, unavailable credentials,
   missing vendor infra, or another true repo-external blocker, record that
   blocker explicitly and stop escalation only at that point.
10. Keep deterministic baselines recorded, but do not let them replace
   live discovery evidence in summaries or decision-making.
11. When the browser-first frontier reaches exhaustion, define the next frontier
    explicitly before ending the iteration.

Decision rules:

- Discovery work should be prioritized by live product signal, not by ease of
  adding another deterministic task.
- MiniWoB and local workflow additions are justified only when they protect a
  shared reusable capability that was first exposed by live external runs.
- If browser-first live runs are unavailable because the repo lacks an adapter,
  the immediate task is to land the adapter on existing repo surfaces, not to
  continue expanding deterministic local workflow ladders.
