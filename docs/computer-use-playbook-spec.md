# Computer-Use Playbook Spec

Status: Draft v0.1
Last updated: 2026-03-23
Audience: desktop runtime, benchmark, inference, tools, and policy teams

## 1. Purpose

This file is the stable playbook for computer-use capability work in this repo.

- `docs/computer-use-live-discovery-plan.md` remains the rolling window for the
  active benchmark frontier and exact slice-by-slice live evidence.
- This playbook is the durable source for doctrine, benchmark maturity, current
  benchmark status, and update rules across MiniWoB++, OSWorld, BrowserGym,
  WebArena, and WorkArena.

## 2. Contract Precedence

- `docs/CIRC.md` is normative for intent resolution. Zero heuristics.
- `docs/CEC.md` is normative for execution. Zero fallbacks after execution
  begins.
- If this playbook conflicts with CIRC or CEC, CIRC and CEC win.
- Benchmarks are evidence sources. They are not routing authorities and they do
  not justify benchmark-local exceptions.

## 3. Current Execution Baseline

- Live benchmark proof currently uses OpenAI-compatible HTTP inference with API
  keys loaded from workspace `.env` when present via
  `crates/cli/tests/live_inference_support.rs`.
- Authoritative benchmark proof currently means
  `COMPUTER_USE_SUITE_MODE=agent` plus
  `COMPUTER_USE_SUITE_AGENT_BACKEND=live_http`.
- The core runtime strategy is the generic desktop step/action pipeline plus
  the clean capability ontology. We are not creating benchmark-specific
  resolver branches, benchmark-specific tool selectors, or benchmark-conditioned
  execution retries.
- The practical doctrine is: make the tools, observation surfaces,
  verification, recovery, and bridge fidelity better so a weaker or "dumber"
  model can still act more intelligently from better grounded primitives.
- Deterministic benchmark runs are regression coverage only. They are not proof
  of live capability.

## 4. Improvement Doctrine

- Improve shared tool surfaces, not benchmark-local tricks.
- Improve typed observation, not prompt folklore.
- Improve verification receipts and judges, not reply-text parsing.
- Improve recovery and bridge fidelity, not heuristic retries.
- Improve ontology cleanliness, not provider or domain aliases.
- When a benchmark exposes a real gap, land the smallest shared fix that would
  help non-benchmark computer use too.
- If the only apparent fix is a benchmark-conditioned exception, that is
  evidence the fix is not allowed.

## 5. Non-Negotiable Invariants

- no ad hoc routing or execution heuristics
- no benchmark-conditioned routing
- no benchmark-named ontology symbols
- no provider-conditioned query shortcutting
- no judge cheating or benchmark-local shortcutting
- no post-execution retries using the real environment as a sandbox
- no "zero provider call" live passes
- no readiness claims from preflight alone

These constraints are not philosophy-only. They are required to stay compliant
with CIRC and CEC while still making the system better.

## 6. Benchmark Maturity Labels

- `integrated_live`: benchmark is part of the repo-real capability loop and is
  allowed to count toward benchmark progress.
- `bridge_alpha`: benchmark has a repo bridge and preflight or smoke coverage,
  but it is not yet part of the main suite of record.
- `dependency_only`: code depends on the benchmark ecosystem, but no generic
  benchmark loop exists yet.
- `absent`: no meaningful repo integration yet.

## 7. Benchmark Registry

Workspace readiness below reflects the latest verified local status for each
surface.

| Surface | Repo maturity | Current benchmark status | Workspace status (last verified) | Next unlock |
| --- | --- | --- | --- | --- |
| MiniWoB++ | `integrated_live` | Primary suite of record. `smoke`, `core`, `workflow*`, and cumulative `stress` are closed live. The post-geometry `catalog` read / lookup / transfer frontier still keeps `read_table`, `read_table_2`, `social_media`, `button_delay`, and now `click_button_sequence` closed, while `phone_book`, `email_inbox`, `stock_market`, and `bisect_angle` remain parked as honest plateaus. Fresh 2026-03-23 exact evidence still makes `miniwob_catalog_chase_circle` the active exact live red: best authoritative rerun `run-1774281832` used one provider-backed `browser__hover {"id":"grp_circ","duration_ms":10000}` and still graded `reward=0.8367`, and revalidation `run-1774283163` stayed red at `reward=0.7948` with the same one-turn hover plan after reverting a losing harness timing experiment. The net effect is an honest startup-budget / bridge-timing plateau rather than a planner-intent miss. The former timed-sequence frontier `miniwob_catalog_button_delay` is now closed live on `run-1774288656`: one provider-backed `browser__click_element {"ids":["btn_one","btn_two"],"delay_ms_between_ids":2000}` passed at `reward=1.0` after widening the generic click follow-up contract so grounded `browser__wait` chains can stay inside the same execution boundary. Fresh 2026-03-23 exact rerun `run-1774290416` now closes `miniwob_catalog_click_button_sequence`: one provider-backed `browser__click_element` on `grp_start` with nested ordered ids `["btn_one","btn_two"]` and `delay_ms_between_ids=100` passed at `raw_reward=1.0` after generalizing the same low-latency ordered-click executor to undelayed batches. The shared ordered-click executor, timed pending signal, and direct bridge regressions `computer_use_suite::harness::tests::timed_ordered_click_sequence_solves_button_delay_directly` plus `computer_use_suite::harness::tests::ordered_click_batch_solves_click_button_sequence_directly` remain green against MiniWoB itself. Fresh 2026-03-22 live reruns on `bisect_angle` (`run-1774227028`, `run-1774227554`, `run-1774227660`, `run-1774227847`) kept improving generic SVG recovery and correction signaling, but the live planner still either submitted early or ignored an explicit grounded correction call, so the slice stays an honest planner plateau. | Locally runnable here when `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR` points at a MiniWoB++ checkout; revalidated on 2026-03-23 with `/tmp/miniwob-plusplus`. The authoritative suite path does not require the Python `miniwob` package or a separately installed host Chromium because the repo bridge uses its own browser cache. The workspace `.env` is again producing provider-backed live calls, exact reruns on `button_delay`, `click_button_sequence`, and `chase_circle` are generating full artifacts on the current code, and both direct ordered-click regressions are green. | Keep `chase_circle` recorded as an honest exact plateau, rerun the full `catalog` audit, then collapse the next exact red from widened evidence. Only after MiniWoB is honestly exhausted again should the next loop move to OSWorld `bridge_alpha` preflight, then smoke. |
| OSWorld | `bridge_alpha` | Standalone preflight contract plus ignored smoke exist through `tools/osworld/osworld_desktop_env_bridge.py`. Not yet part of `computer_use_suite` proper. | Preflight is still blocked locally, but the blocker chain is now sharper. On the default host it reports no configured `desktop_env` source or package, missing `gymnasium`, and no `docker`, `vmrun`, or `VBoxManage`. With `IOI_OSWORLD_SOURCE_ROOT` pointed at an official OSWorld checkout, `desktop_env` becomes discoverable and the blockers collapse to missing `gymnasium` plus no supported provider command. The host Python also lacks `pip`, `ensurepip`, and `venv`, so installing missing Python deps is itself externally blocked by missing system packages. `IOI_OSWORLD_CLIENT_PASSWORD` remains unset, which is still warning-only. | Install a supported OSWorld Python dependency bootstrap plus one real provider command, rerun preflight, then run smoke. |
| BrowserGym (generic) | `dependency_only` | Present only as the substrate for WorkArena. No generic BrowserGym benchmark adapter or suite of record exists yet. | Not locally runnable; `browsergym` is not installed. | Build a generic BrowserGym adapter with preflight, smoke, and typed validation shape instead of hardcoding one benchmark family at a time. |
| WorkArena | `bridge_alpha` | BrowserGym-backed bridge exists with `preflight`, `prepare`, and `validate`. Rust has a preflight contract test and an ignored prepare smoke. Not yet part of `computer_use_suite` proper. | Preflight blocked locally: missing `playwright`, missing `browsergym.workarena`, missing `INSTANCE_XOR_SEED`, and missing ServiceNow or Hugging Face access. | Make preflight green, run prepare or validate smoke against real instance access, then unify judge and artifact conventions with the main suite. |
| WebArena | `absent` | No repo integration or meaningful references are present as of 2026-03-22. | No local readiness path because no adapter exists. | Add a bridge or adapter, preflight, smoke, and typed validation before treating it as a tracked benchmark. |

## 8. Benchmark-Specific Source of Truth

- MiniWoB++ benchmark frontier and run-level evidence:
  `docs/computer-use-live-discovery-plan.md`
- MiniWoB++ suite entrypoint and task-set surface:
  `crates/cli/tests/computer_use_suite`
- OSWorld bridge and repo contract tests:
  `tools/osworld/osworld_desktop_env_bridge.py` and
  `crates/cli/tests/osworld_live_e2e.rs`
- WorkArena bridge and repo contract tests:
  `tools/browsergym/workarena_cdp_bridge.py` and
  `crates/cli/tests/workarena_live_e2e.rs`

## 9. What Counts as Progress

### 9.1 Integrated Live Benchmarks

For `integrated_live` benchmarks, progress requires:

- provider-backed live inference
- non-zero provider call count
- full run artifacts
- typed judge evidence
- either a real pass or an honest plateau with canonical failure class

### 9.2 Bridge Alpha Benchmarks

For `bridge_alpha` benchmarks, progress requires:

- preflight that can report either green or explicit blockers
- at least one smoke or prepare path that touches the real benchmark surface
- typed output describing goal, observations, reward, or validation state
- a clear promotion path toward unified suite artifacts and judging

Preflight green alone does not equal benchmark capability.

### 9.3 Dependency-Only or Absent Benchmarks

For `dependency_only` or `absent` benchmarks, progress means:

- add repo adapter or bridge
- add preflight
- add smoke
- add typed validation contract
- only then discuss benchmark-driven improvement loops

## 10. Update Protocol

- Update this document when benchmark maturity changes, workspace readiness
  changes materially, or a benchmark moves between `absent`,
  `dependency_only`, `bridge_alpha`, and `integrated_live`.
- Update `docs/computer-use-live-discovery-plan.md` when the active MiniWoB
  frontier, canonical red slice, or canonical run evidence changes.
- Record absolute dates for local readiness checks and benchmark state changes.
- Do not overwrite an honest plateau claim without a new authoritative live run
  or a clearly greener bridge status.

## 11. Near-Term Priorities

- Keep MiniWoB++ as the primary integrated-live evidence engine, resume the
  active exact slice `miniwob_catalog_chase_circle`, then widen back to full
  `catalog`.
- Do not reopen parked MiniWoB slices without a broader shared planner or
  observation hypothesis; avoid slice-local retries.
- After MiniWoB is honestly exhausted again, bring OSWorld to green preflight
  and smoke on a supported provider.
- Bring WorkArena to green preflight plus real prepare or validate smoke on a
  reachable instance.
- Build a generic BrowserGym adapter before adding more BrowserGym-family
  benchmarks one by one.
- Treat WebArena as not started until a real adapter exists.

## 12. Anti-Goals

We are explicitly not doing any of the following:

- benchmark-specific routing branches
- prompt-only benchmark patches
- task-id keyed planner behavior
- domain or provider aliases in ontology space
- reply-text-only success gating
- post-execution retry loops against the real environment
- fake "smartness" from hidden heuristics that do not generalize

The intended way to make the model look smarter is to make the capability
surface more truthful, grounded, and composable while keeping the runtime
generic and contract-clean.

## 13. Operator Prompt

- The reusable autonomous operator prompt for this workflow lives in
  `docs/computer-use-autonomy-prompt.md`.
