# Browser / Computer-Use Discovery Plan

This file is the single authoritative backlog, status ledger, benchmark snapshot,
and living roadmap for browser/computer-use discovery. Historical MiniWoB and
local workflow results remain recorded here as regression and reproduction
baselines; browser-first external discovery was exhausted in-repo by true
repo-external blockers, so the active frontier is now the next cross-app bring-
up lane.

- primary discovery lane: live inference on browser-first external benchmarks
- secondary reproduction lane: deterministic local reproductions for reusable gaps
- regression lane: MiniWoB plus local workflow fixtures

## Status

Current phase:

- Active frontier: carry the repo's proven live-inference computer-use stack from
  the now-blocked browser-first external lane into the smallest viable OSWorld /
  OSWorld-Verified cross-app bring-up surface.
- Frontier discipline: exhaust the browser-first external frontier before moving
  to cross-app benchmarks. Do not actively advance WorkArena/browser-first and
  OSWorld/cross-app in parallel.
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
- The current live local gap has moved twice on the `gpt-4o-mini` lane:
  `run-1773434964` still hit `Failed("Resources/Retry limit exceeded")` after
  typed success, `run-1773435501` auto-queued a repo-real `browser__snapshot`
  verification step and improved the terminal state to `Completed(None)`, and
  `run-1773436568` narrowed the remaining root to a smaller shared
  `verification_gap`: instruction-contract success criteria were still too vague
  to let the verified browser snapshot auto-complete. That local
  post-success terminalization gap is now closed authoritatively by
  `run-1773436925` on `gpt-4o-mini`.
- The latest authoritative local browser smoke state is green on both live
  models:
  - `run-1773436925`: `HttpInferenceRuntime` + `gpt-4o-mini` cleanly completed
    from queued `browser__snapshot` verification with
    `success_criteria=status_text.updated_to_done`
  - `run-1773437051`: `HttpInferenceRuntime` + `gpt-4o` remained clean after one
    transient diagnostic intent-resolution availability failure under
    `run-1773436988`
- The browser-first external frontier remains explicitly blocked by a true
  repo-external constraint: WorkArena still lacks the required Python
  dependencies and benchmark credentials/access, and no alternate
  repo-integrated browser-first external adapter exists today.
- A smallest-viable OSWorld DesktopEnv adapter surface now exists via
  `crates/cli/tests/osworld_live_e2e.rs` and
  `tools/osworld/osworld_desktop_env_bridge.py`, but the current environment is
  blocked before smoke execution by missing `desktop_env`, missing `gymnasium`,
  the absence of any supported provider command (`docker`, `vmrun`, or
  `VBoxManage`), and the host Python currently lacks a safe local package
  bootstrap path (`pip`, `ensurepip`, and working `venv` are unavailable).
- Browser-first external discovery is therefore formally exhausted for the
  current environment and repo state; cross-app OSWorld bring-up is now the
  active frontier rather than a parallel lane.

Immediate goals:

1. Keep the live-inference browser proof path green on the repo-real
   `DesktopAgentService` / `BrowserDriver` stack as regression coverage now that
   the local post-success terminalization gap is closed.
2. Convert the landed OSWorld DesktopEnv bridge from typed preflight to a
   quickstart-style cross-app smoke slice as soon as the repo-external
   environment blockers are removed.
3. Once the OSWorld environment smoke is ready, push immediately to the first
   live-inference cross-app slice on the same runtime/receipt discipline rather
   than drifting back into deterministic-local work.
4. Backfill deterministic local reproduction only if a future live artifact
   proves another reusable shared gap.

Exit criteria for the current phase:

- preserve the authoritative artifact-backed proof that real provider-backed
  inference is already working on the repo-real browser/computer-use path
- one typed cross-app OSWorld bring-up slice, or a true repo-external blocker
  documented at that frontier
- the first live-inference cross-app rung clearly defined after bring-up
- the next frontier after the current cross-app iteration clearly defined in this
  document

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
- Authoritative local live browser proof rerun after duplicate-success salience
  and noop handling:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773434964`
  - Typed outcome: `dom_contains_done=true`, but final agent status
    `Failed("Resources/Retry limit exceeded")`
  - Classification: authoritative capability proof; the original immediate
    replay failure was partially closed, but the remaining gap still
    re-entered recovery after a later replay
- Authoritative local live browser proof rerun after auto-queued browser
  verification:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773435501`
  - Typed outcome: `dom_contains_done=true`, final agent status
    `Completed(None)`, queued browser verification snapshot executed, but no
    final reply / no clean `agent__complete`
  - Classification: authoritative capability proof with the current smallest
    honest remaining class narrowed to `planner_gap` on post-verified-snapshot
    terminalization
- Authoritative local live browser control rerun after the duplicate-verification
  fix:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773435563`
  - Typed outcome: `dom_contains_done=true`, clean `agent__complete`
  - Classification: authoritative regression control showing the stronger-model
    local browser lane remains green
- Authoritative local live browser rerun after shared browser-snapshot
  auto-completion:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773436568`
  - Typed outcome: `dom_contains_done=true`, final agent status
    `Completed(None)`, final reply absent, termination via
    `system::max_steps_reached`
  - Classification: authoritative capability proof with the previously suspected
    `planner_gap` corrected to a narrower `verification_gap`; the shared browser
    completion hook was present, but under-specified instruction-contract success
    criteria (`status_text.updated`) prevented verified auto-completion
- Authoritative local live browser rerun after instruction-contract success target
  enrichment:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o-mini cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o-mini`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773436925`
  - Typed outcome: `dom_contains_done=true`, final agent status
    `Completed(Some(...))`, final reply emitted, queued browser verification
    snapshot auto-completed with
    `success_criteria=status_text.updated_to_done`
  - Classification: authoritative local browser smoke; the narrowed shared local
    `verification_gap` is closed on the `gpt-4o-mini` lane
- Diagnostic local live browser control rerun while revalidating after the shared
  contract fix:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: failed diagnostically
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773436988`
  - Typed outcome: `Paused("Waiting for intent clarification")`,
    `dom_contains_done=false`, no action step executed
  - Classification: diagnostic transient `infra_or_bridge_gap`; intent
    resolution returned `resolver.unclassified` with
    `embedding_model_id="resolver.unavailable"` and zeroed ranking scores
- Authoritative local live browser control rerun after the transient intent
  resolver failure:
  - Command:
    `IOI_BROWSER_LIVE_MODELS=gpt-4o cargo test -p ioi-cli --test browser_live_runtime_e2e browser_live_http_runtime_smoke -- --ignored --exact --nocapture`
  - Result: passed
  - Runtime/provider/model: `HttpInferenceRuntime` against
    `https://api.openai.com/v1/chat/completions` with `gpt-4o`
  - Artifact root:
    `crates/cli/target/browser_live_runtime/run-1773437051`
  - Typed outcome: `dom_contains_done=true`, clean `agent__complete`, final
    reply emitted
  - Classification: authoritative regression control showing the stronger-model
    local browser lane remains green after the shared contract fix
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
- Direct WorkArena bridge preflight recorded:
  - Command:
    `python3 tools/browsergym/workarena_cdp_bridge.py preflight`
  - Result: blocked diagnostic
  - Classification: true repo-external blocker confirmed with typed details:
    missing `playwright`, missing or unusable `browsergym.workarena`, missing
    `INSTANCE_XOR_SEED`, and missing ServiceNow / Hugging Face benchmark access
- Refreshed WorkArena blocker validation after the local browser rung closed:
  - Command:
    `cargo test -p ioi-cli --test workarena_live_e2e workarena_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact`
  - Result: passed as typed diagnostic preflight
  - Classification: no change; the repo-integrated WorkArena surface is still
    bring-up ready, but actual external execution remains blocked outside the repo
  - Command:
    `python3 tools/browsergym/workarena_cdp_bridge.py preflight`
  - Result: blocked diagnostic
  - Classification: true repo-external blocker unchanged; still missing
    `playwright`, `browsergym.workarena`, `gymnasium`, `huggingface_hub`,
    `numpy`, `INSTANCE_XOR_SEED`, and benchmark credentials/access
- Shared-fix targeted tests recorded:
  - `cargo test -p ioi-services --lib cognition::tests -- --nocapture`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::intent_resolver::tests::scope_policy::ui_interaction_scope_allows_browser_safe_followups' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::tools::discovery::tests::visual_foreground_browser_window_exposes_browser_followups_for_ui_interaction' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::deterministic_recovery_does_not_replay_browser_snapshot_after_duplicate_no_effect' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::duplicate_browser_snapshot_incident_forbids_navigation_remedies' -- --exact`
  - `cargo test -p ioi-services --lib 'agentic::desktop::service::step::incident::recovery::tests::deterministic_recovery_prefers_browser_snapshot_for_browser_target_not_found' -- --exact`
  - `cargo test -p ioi-services --lib browser_observation_context_ -- --nocapture`
  - `cargo test -p ioi-services 'agentic::desktop::service::step::action::support::tests::action_fingerprint_label_roundtrips_when_recorded_with_step' -- --exact`
  - `cargo test -p ioi-services 'agentic::desktop::service::step::action::processing::phases::execute_tool_phase::duplicate::tests'`
  - `cargo test -p ioi-services 'agentic::desktop::service::step::cognition::history::tests'`
  - Result: all passed
- Shared-fix targeted tests for the new browser completion and instruction-
  contract path recorded:
  - `cargo test -p ioi-services browser_snapshot_completion -- --nocapture`
  - `cargo test -p ioi-services 'agentic::desktop::service::step::queue::processing::completion::tests'`
  - `cargo test -p ioi-services 'agentic::desktop::service::step::intent_resolver::instruction_contract::tests' -- --nocapture`
  - Result: all passed
- OSWorld bridge bring-up validation recorded:
  - Command:
    `python3 -m py_compile tools/osworld/osworld_desktop_env_bridge.py`
  - Result: passed
  - Classification: bridge script syntax validated
  - Command:
    `cargo test -p ioi-cli --test osworld_live_e2e osworld_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact --nocapture`
  - Result: passed as typed diagnostic preflight
  - Classification: cross-app adapter bring-up succeeded, but actual OSWorld
    smoke execution is still blocked outside the repo/runtime environment
  - Command:
    `python3 tools/osworld/osworld_desktop_env_bridge.py preflight`
  - Result: blocked diagnostic
  - Classification: true repo-external blocker confirmed with typed details:
    missing `desktop_env`, missing `gymnasium`, and no supported provider
    command (`docker`, `vmrun`, or `VBoxManage`) in the current environment
- OSWorld dependency bootstrap attempts recorded:
  - Command:
    `python3 -m pip install --user desktop-env gymnasium`
  - Result: failed diagnostically with `/usr/bin/python3: No module named pip`
  - Command:
    `python3 -m ensurepip --user`
  - Result: failed diagnostically with `/usr/bin/python3: No module named ensurepip`
  - Command:
    `python3 /tmp/get-pip.py --user`
  - Result: failed diagnostically with `externally-managed-environment`
    (PEP 668)
  - Command:
    `python3 -m venv /tmp/ioi-osworld-venv`
  - Result: failed diagnostically because `ensurepip` / `python3.12-venv` is
    unavailable on the host
  - Classification: the missing OSWorld Python dependencies are now confirmed as
    a true host-level repo-external blocker in this environment, not an in-repo
    integration gap

Required first validations for the new plan:

1. Preserve the existing proof that the active browser path is using a real
   provider-backed inference runtime rather than `MiniwobAgentRuntime`,
   `MockInferenceRuntime`, or the placeholder `StandardInferenceRuntime`.
2. Preserve the existing proof that the live path is the repo's real
   `DesktopAgentService` plus `BrowserDriver` stack.
3. After the browser-first external frontier is explicitly blocked, land a typed
   OSWorld bring-up surface and record either a ready smoke rung or the exact
   repo-external blockers on that cross-app lane.

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
- WorkArena external execution is currently blocked outside the repo by missing
  Python packages (`playwright`, `browsergym.workarena`, `gymnasium`,
  `huggingface_hub`, `numpy`), missing `INSTANCE_XOR_SEED`, and unavailable
  ServiceNow / Hugging Face access.
- OSWorld cross-app execution is currently blocked outside the repo/runtime
  environment by missing Python packages (`desktop_env`, `gymnasium`) and the
  absence of any supported provider command (`docker`, `vmrun`, `VBoxManage`).
  The host also lacks `pip`, `ensurepip`, and working `python3 -m venv`, so the
  missing Python dependencies cannot be bootstrapped safely in user space from
  this environment. `IOI_OSWORLD_CLIENT_PASSWORD` is also unset, which is a
  retained readiness warning for tasks that require sudo or proxy setup.
- The earlier `gpt-4o` cognition refusal under
  `crates/cli/target/browser_live_runtime/run-1773430304` is now a historical
  diagnostic, not a current blocker; `run-1773433420` passed after prompt-shape
  hardening.
- The previously active local post-success terminalization issue on
  `gpt-4o-mini` is now closed on the current authoritative local slice:
  - `run-1773436568` corrected the remaining local issue to a narrow
    `verification_gap` caused by under-specified instruction-contract success
    criteria
  - `run-1773436925` closed that local gap cleanly on `gpt-4o-mini`
- `run-1773436988` is a retained diagnostic-only transient
  `infra_or_bridge_gap`: intent resolution returned
  `resolver.unclassified` with `embedding_model_id="resolver.unavailable"`, but
  the exact rerun `run-1773437051` passed cleanly, so this is not the current
  blocking frontier.
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
- 2026-03-13: Added shared post-success duplicate handling across the repo-real
  browser path by:
  - preserving action-fingerprint success labels for duplicate browser replays
  - surfacing a high-salience recent-success block inside browser cognition
  - converting immediate replays of previously successful identical browser
    actions into typed noops instead of recovery-triggering errors
  The targeted duplicate and cognition-history tests passed, but authoritative
  `gpt-4o-mini` rerun `run-1773434964` showed the gap only partially closed:
  the first replay no longer triggered recovery, but a later replay still did.
- 2026-03-13: Added shared automatic browser verification queueing when a prior-
  successful browser interaction is replayed:
  - duplicate success provenance is now preserved as `success_duplicate_skip`
  - duplicate replays of prior-successful browser interactions now queue a
    repo-real `browser__snapshot` verification step on the existing execution
    queue
  Targeted duplicate tests passed. Authoritative `gpt-4o-mini` rerun
  `run-1773435501` confirmed the queued verification snapshot executed and moved
  terminal state from `Failed("Resources/Retry limit exceeded")` to
  `Completed(None)`, but the model still did not cleanly finalize after verified
  state. `gpt-4o` regression control `run-1773435563` remained clean.
- 2026-03-13: Added shared browser-snapshot success-criteria auto-completion on
  both direct and queued browser snapshot paths. The runtime can now finalize a
  mutating `UiInteraction` from typed snapshot evidence when all recognized
  instruction-contract success criteria are satisfied, and it emits terminal chat
  reply bindings on that path. Targeted tests passed under
  `browser_snapshot_completion` plus queue-completion coverage. Authoritative
  `gpt-4o-mini` rerun `run-1773436568` proved the remaining local issue was no
  longer post-verified-snapshot planning drift; the browser had typed success,
  but the helper could not fire because the instruction contract still carried an
  under-specified success criterion (`status_text.updated`).
- 2026-03-13: Strengthened instruction-contract terminal-state fidelity by:
  - enriching vague success criteria from explicit user end-state language, such
    as upgrading `status_text.updated` to `status_text.updated_to_done`
  - adding prompt examples that force terminal values into
    `successCriteria` whenever the user provides them
  Targeted tests passed under
  `agentic::desktop::service::step::intent_resolver::instruction_contract::tests`.
  Authoritative `gpt-4o-mini` rerun `run-1773436925` then completed cleanly from
  queued verified snapshot evidence with
  `success_criteria=status_text.updated_to_done`.
- 2026-03-13: Reran the `gpt-4o` control lane after the shared contract fix.
  `run-1773436988` failed diagnostically before any action step with
  `resolver.unclassified` and `embedding_model_id="resolver.unavailable"`,
  which is a transient `infra_or_bridge_gap` rather than a browser-action
  regression. The exact rerun `run-1773437051` returned to a clean
  authoritative pass.
- 2026-03-13: Reconfirmed the WorkArena external blocker directly with
  `python3 tools/browsergym/workarena_cdp_bridge.py preflight`. The bridge still
  lacks the repo-external Python packages and credentials needed for an actual
  browser-first external slice.
- 2026-03-13: Added the smallest viable OSWorld cross-app bring-up surface in
  `crates/cli/tests/osworld_live_e2e.rs` and
  `tools/osworld/osworld_desktop_env_bridge.py`. The bridge follows the official
  DesktopEnv quickstart pattern for a future smoke rung, but the current
  environment is blocked before execution by missing `desktop_env`, missing
  `gymnasium`, and no supported provider command (`docker`, `vmrun`, or
  `VBoxManage`).
- 2026-03-13: Attempted to reduce the OSWorld bring-up blockers in-place, but
  the host Python environment is externally managed and lacks `pip`,
  `ensurepip`, and working `python3 -m venv`. That means the missing
  DesktopEnv/gymnasium dependencies cannot be installed safely from this repo
  session, which tightens the OSWorld blocker to a true host-level
  `infra_or_bridge_gap`.

## Benchmark Snapshot

Active discovery benchmarks:

| Benchmark lane | Status | Authoritative result | Artifact root | Notes |
| --- | --- | --- | --- | --- |
| Live browser path proof / local browser smoke | authoritative green with retained diagnostic transient | `gpt-4o-mini` clean on `run-1773436925`; `gpt-4o` clean on `run-1773437051` after one transient diagnostic `resolver.unavailable` run | `crates/cli/target/browser_live_runtime/run-1773436925`, `run-1773436988`, `run-1773437051` | real `HttpInferenceRuntime` + repo-real browser/computer-use stack; the shared local post-success `verification_gap` is now closed, and the remaining active frontier blocker is external |
| Live browser-first external benchmark | blocked by true repo-external constraint | none yet | `crates/cli/tests/workarena_live_e2e.rs`, `tools/browsergym/workarena_cdp_bridge.py` | WorkArena preflight remains typed and passing, but direct preflight still reports missing Python deps plus missing benchmark credentials/access; no alternate repo-integrated browser-first external adapter exists today |
| Live cross-app external benchmark | blocked by true repo-external constraint | none yet | `crates/cli/tests/osworld_live_e2e.rs`, `tools/osworld/osworld_desktop_env_bridge.py` | the next frontier is now active and has a typed preflight surface, but the current environment lacks `desktop_env`, `gymnasium`, any supported provider command for DesktopEnv bring-up, and a safe local pip/venv bootstrap path |

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
| `observation_gap` | closed on the current authoritative local slice | partially closed in local baselines | semantic snapshot evidence now survives incident chatter and supports clean authoritative completion on both live local lanes |
| `verification_gap` | closed on the current authoritative local slice | partially closed in local baselines | the remaining local issue narrowed to under-specified success criteria on `run-1773436568`, then closed via instruction-contract enrichment on `run-1773436925` |
| `recovery_gap` | not active on the current authoritative local slice | partially closed in local baselines | keep duplicate snapshot and page-leaving remedy guards in place; reopen only on new live evidence |
| `planner_gap` | not active on the current authoritative local slice | several prior labels corrected away in local baselines | previous post-verified-snapshot suspicion was corrected to the smaller `verification_gap` and then closed on the local smoke |
| `infra_or_bridge_gap` | active current blocker class | known from prior local diagnostics | current active blockers are WorkArena external Python dependencies plus benchmark credentials/access, OSWorld DesktopEnv/provider prerequisites, and the retained transient intent-resolution availability failure under `run-1773436988` |

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
   Status: blocked on actual external execution by a true repo-external constraint.
   Objective:
   - land the smallest viable BrowserGym-style integration on the existing repo
     stack
   Preferred targets:
   - WorkArena first if it is the lightest realistic path
   - if WorkArena is truly repo-external blocked, use another browser-first
     benchmark in the same frontier before switching to cross-app work
   - WebArenaVerified first if its verification surfaces are easier to make typed
   Requirements:
   - no parallel execution stack
   - no benchmark-conditioned routing or task-name hacks
   - use typed observations and typed postconditions
   Exit criteria:
   - authoritative smoke slice runs end to end on a live browser-first benchmark
   Next smallest pending rung once blockers clear:
   - target:
     WorkArena bridge prepare smoke on the repo-real `BrowserDriver` session
   - exact command shape:
     `cargo test -p ioi-cli --test workarena_live_e2e workarena_bridge_prepare_smoke_uses_browser_driver_session -- --ignored --exact --nocapture`
   - expected artifact root:
     temporary bridge `state_path` emitted by the test; no dedicated repo
     artifact directory exists yet for this rung
   - smallest honest exit criterion:
     preflight reports ready, the bridge returns `ok=true`, emits a non-empty
     goal, and writes the task state file against the repo-real browser session
   Recorded evidence:
   - Command:
     `cargo test -p ioi-cli --test workarena_live_e2e workarena_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact`
   - Outcome:
     typed preflight passed; actual external run still blocked by missing
     dependencies / credentials outside the repo
   - Command:
     `python3 tools/browsergym/workarena_cdp_bridge.py preflight`
   - Outcome:
     blocked diagnostic with explicit blockers: missing `playwright`, missing
     `browsergym.workarena`, missing `INSTANCE_XOR_SEED`, and missing benchmark
     credentials/access

3. Browser-first live smoke slice
   Status: closed for the local live browser slice.
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
   - Authoritative progression:
     `crates/cli/target/browser_live_runtime/run-1773431386`,
     `run-1773433420`, `run-1773433583`, `run-1773434964`,
     `run-1773435501`, `run-1773435563`, `run-1773436568`,
     `run-1773436925`, `run-1773437051`
   - Diagnostic transient:
     `crates/cli/target/browser_live_runtime/run-1773436988`
   - Current interpretation:
     the local live browser slice is now green on both live models; the next
     harder browser-first rung remains the external WorkArena slice, which is
     currently blocked by true repo-external constraints

4. Shared browser-first gap closure
   Status: closed for the current local browser gap.
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
     duplicate snapshot page-leaving recovery drift, semantic browser snapshot
     evidence loss, local `gpt-4o` refusal on placeholder-visual browser prompts,
     duplicate-success replay drift, queued browser verification, and the final
     narrowed local `verification_gap` caused by under-specified instruction-
     contract success criteria
   - recorded closure evidence:
     `run-1773436925` on `gpt-4o-mini` and `run-1773437051` on `gpt-4o`
   - next read:
     carry the hardened browser path into the first external slice when the
     WorkArena blockers clear; if the browser-first external frontier remains
     blocked, switch the next frontier to OSWorld / OSWorld-Verified rather than
     expanding deterministic-local coverage

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
   Status: reached; browser-first external frontier is blocked by a true
   repo-external constraint.
   Objective:
   - determine whether browser-first live discovery is still yielding product
     signal
   Exit criteria:
   - either continue browser-first escalation, or define the next frontier as
     cross-app OSWorld / OSWorld-Verified
   Current read:
   - browser-first discovery yielded a product-relevant shared local
     `verification_gap`, and that gap is now closed on the authoritative local
     browser slice
   - browser-first external escalation is explicitly blocked by a true
     repo-external constraint: WorkArena still lacks the required Python
     dependencies and benchmark credentials/access, and no alternate
     repo-integrated browser-first external adapter exists today
   - the next frontier beyond the blocked browser-first external rung is
     OSWorld / OSWorld-Verified; do not advance it in parallel with browser-first
     work

7. Cross-app escalation
   Status: in progress; blocked on actual OSWorld execution by a true
   repo-external constraint in the current environment.
   Objective:
   - move to OSWorld / OSWorld-Verified only after browser-first discovery is
     explicitly marked exhausted or blocked by a true repo-external constraint
   Next frontier target:
   - land and validate the smallest typed OSWorld DesktopEnv bring-up surface on
     repo surfaces, then convert it to a quickstart-style smoke slice once
     blockers clear
   Requirements:
   - keep the same artifact discipline and classification rules
   - prefer shared fixes over benchmark-local workarounds
   Next smallest pending rung once blockers clear:
   - target:
     OSWorld DesktopEnv quickstart smoke on the resolved provider
   - exact command shape:
     `cargo test -p ioi-cli --test osworld_live_e2e osworld_bridge_quickstart_smoke_runs_minimal_task -- --ignored --exact --nocapture`
   - expected artifact root:
     temporary `result_path` emitted by the test; no dedicated repo artifact
     directory exists yet for this rung
   - smallest honest exit criterion:
     preflight reports ready, the bridge returns `ok=true`, writes the result
     JSON, and reports non-empty reset/step observation keys from DesktopEnv
   Recorded evidence:
   - Command:
     `python3 -m py_compile tools/osworld/osworld_desktop_env_bridge.py`
   - Outcome:
     passed
   - Command:
     `cargo test -p ioi-cli --test osworld_live_e2e osworld_bridge_preflight_reports_repo_external_blockers_or_ready_state -- --exact --nocapture`
   - Outcome:
     typed preflight passed; adapter bring-up is wired into repo tests
   - Command:
     `python3 tools/osworld/osworld_desktop_env_bridge.py preflight`
   - Outcome:
     blocked diagnostic with explicit blockers: missing `desktop_env`, missing
     `gymnasium`, and no supported provider command (`docker`, `vmrun`, or
     `VBoxManage`) in the current environment
   - Command:
     `python3 -m pip install --user desktop-env gymnasium`
   - Outcome:
     failed because `/usr/bin/python3` has no `pip`
   - Command:
     `python3 -m venv /tmp/ioi-osworld-venv`
   - Outcome:
     failed because `ensurepip` / `python3.12-venv` is unavailable, confirming
     the missing Python dependencies cannot be safely bootstrapped from this
     host session
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
   classifying the remaining issue as the smallest honest class (for example
   `verification_gap`, then a later-narrowed `planner_gap`) with the corrected
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
12. Do not alternate between browser-first external work and cross-app external
    work within the same iteration band; keep one active frontier at a time.

Decision rules:

- Discovery work should be prioritized by live product signal, not by ease of
  adding another deterministic task.
- MiniWoB and local workflow additions are justified only when they protect a
  shared reusable capability that was first exposed by live external runs.
- If browser-first live runs are unavailable because the repo lacks an adapter,
  the immediate task is to land the adapter on existing repo surfaces, not to
  continue expanding deterministic local workflow ladders.
- Do not switch from WorkArena/browser-first to OSWorld/cross-app just because
  the latter looks interesting; switch only after the browser-first frontier is
  explicitly exhausted or hard-blocked.
