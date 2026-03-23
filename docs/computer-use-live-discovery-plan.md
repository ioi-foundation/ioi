# Computer-Use Live Discovery Plan

This file is the single authoritative living spec for benchmark-driven
computer-use improvement in this repo. It is intentionally a rolling window,
not a changelog.

For the stable doctrine, benchmark registry, and cross-benchmark status across
MiniWoB++, OSWorld, BrowserGym, WebArena, and WorkArena, see
`docs/computer-use-playbook-spec.md`.

## Scope

- active family: `crates/cli/tests/computer_use_suite`
- active objective: improve generic computer-use capability through
  provider-backed live runs on the repo-real suite
- current frontier: fresh exact live evidence on 2026-03-23 now centers the
  MiniWoB `catalog` frontier on `miniwob_catalog_chase_circle`; best
  authoritative red `run-1774281832` used one provider-backed
  `browser__hover {"id":"grp_circ","duration_ms":10000}` and still graded
  `reward=0.8367`, while revalidation `run-1774283163` stayed red at
  `reward=0.7948` after reverting a losing harness timing experiment
- downstream objective: record the timed-hover plateau honestly, then widen
  back to a full `catalog` audit to find the next exact red on the current
  code; OSWorld stays queued behind MiniWoB until the integrated suite is
  honestly exhausted again

## Method Invariants

- live-inference-first
- benchmark-driven
- no ad hoc heuristics
- no benchmark-conditioned routing
- no cheating against judges
- shared fixes only: runtime, observation, verification, recovery, bridge, or
  generic tool surfaces
- exact failing live slice first, broader family second
- cumulative sets are audit rungs, not the inner-loop dev target

## Validation Rules

- only provider-backed `computer_use_suite` agent runs count as benchmark
  progress
- required env for benchmark proof:
  - `COMPUTER_USE_SUITE_MODE=agent`
  - `COMPUTER_USE_SUITE_AGENT_BACKEND=live_http`
- allowed live inference surfaces:
  - `HttpInferenceRuntime`
  - `VerifiedHttpRuntime` if cleaner on existing wiring
- these do not count as proof of live inference:
  - `MiniwobAgentRuntime`
  - `MockInferenceRuntime`
  - `StandardInferenceRuntime`
- required live artifacts per authoritative run:
  - `agent_state.json`
  - `inference_trace.json`
  - `inference_calls.json`
- if a live run records zero provider calls, treat it as failure, not pass
- deterministic `oracle`, deterministic `runtime`, and deterministic `agent`
  runs are regression-only

## Status

Current benchmark position:

- full `smoke` is closed live
- full `core` is closed live
- full `workflow`, `workflow_rich`, `workflow_audit`, `workflow_mutation`,
  and `workflow_reorder` are closed live
- full cumulative `stress` is closed live at `19/19` on `run-1773498002`
- rung 5 sentinel `miniwob_catalog_read_table` is now closed live on
  `run-1773530273`
- rung 5 exact widening slice `miniwob_catalog_read_table_2` is now closed
  live on `run-1773530865`
- rung 5 exact slice `miniwob_catalog_phone_book` is now honestly plateaued on
  `run-1773537614` after shared verification and planner-prompt fixes moved
  the failure to persistent target-id hallucination
- rung 5 exact slice `miniwob_catalog_email_inbox` is now honestly plateaued on
  `run-1773539581` after shared mailbox-intent suppression, icon-control
  observation surfacing, raw-id prompt compaction, and action-label
  disambiguation fixes moved the failure through multiple planner modes without
  closing the slice
- rung 5 exact slice `miniwob_catalog_stock_market` is now honestly plateaued
  on `run-1773542003` after shared browser recovery, browser observation, and
  browser queue-timeout fixes moved the failure to a buyable live page state
  that still lacked a usable post-wait semantic snapshot
- rung 5 exact slice `miniwob_catalog_social_media` is now closed live on
  `run-1774201441` after shared DOM-fallback row-action surfacing and
  actionable exact-target ranking fixes exposed the real Reply control
- workspace `.env` is again producing provider-backed MiniWoB calls on
  2026-03-23, so authoritative live reruns are unblocked
- shared follow-up fixes are now landed locally:
  `browser__click_element` supports timed ordered `ids` via
  `delay_ms_between_ids`, the executor measures that delay at click dispatch
  time, and prompt grounding now emits a dedicated pending signal for already
  grounded timed click sequences
- the direct bridge regressions
  `computer_use_suite::harness::tests::timed_ordered_click_sequence_solves_button_delay_directly`
  and
  `computer_use_suite::harness::tests::ordered_click_batch_solves_click_button_sequence_directly`
  now pass against MiniWoB itself, so both the timed and undelayed ordered
  two-click executor paths are locally verified independent of the current
  exact frontier
- fresh authoritative exact rerun `run-1774288656` now closes
  `miniwob_catalog_button_delay` live with `1` provider call on `gpt-4o`; the
  model chose one grounded ordered `browser__click_element` on `btn_one` then
  `btn_two` with `delay_ms_between_ids=2000`, proving the shared timed-sequence
  path end to end
- fresh authoritative exact rerun `run-1774290416` now closes
  `miniwob_catalog_click_button_sequence` live with `1` provider call on
  `gpt-4o`; the model chose a grounded start-gate
  `browser__click_element {"id":"grp_start","continue_with":{"name":"browser__click_element","ids":["btn_one","btn_two"],"delay_ms_between_ids":100}}`,
  and the generalized ordered-click executor closed the slice at
  `raw_reward=1.0`
- fresh exact live reruns on 2026-03-23 now center the active red on
  `miniwob_catalog_chase_circle`
- canonical best red `run-1774281832` is provider-backed with full artifacts
  and `1` provider call on `gpt-4o`; the model chose
  `browser__hover {"id":"grp_circ","duration_ms":10000}` immediately, tracked
  selector `#circ` for the full hover, and still finished at `reward=0.8367`
- revalidation `run-1774283163` reverted a losing harness timing experiment and
  still stayed red at `reward=0.7948` with the same one-turn hover plan,
  confirming the slice is a startup-budget plateau rather than a planner-intent
  miss
- fresh live reruns on `miniwob_catalog_bisect_angle`
  (`run-1774227028`, `run-1774227554`, `run-1774227660`, `run-1774227847`)
  kept the slice red while materially sharpening the plateau:
  - `run-1774227028` confirmed the farther first probe still improves the raw
    geometry to `raw_reward=0.9312573`, but the planner still submitted early
  - `run-1774227554` proved the new offset-aware correction signal changed
    behavior, but the compacted tail still dropped the corrective coordinates
    and the planner guessed a bad second click
  - `run-1774227660` proved the corrective coordinates survived truncation, but
    the planner still ignored them and wandered into extra synthetic clicks
  - `run-1774227847` proved the stronger exact-JSON next-step contract still
    did not move the live planner off the premature submit path
- the net effect is a cleaner honest plateau on `bisect_angle`: shared SVG
  observation, decimal probe precision, post-click geometry verification, and
  offset-aware correction surfaces are all better, but the remaining red is
  planner compliance rather than a missing primitive or bridge gap

Current frontier:

- rung 4 MiniWoB `catalog` is plateaued at exact red slice
  `miniwob_catalog_bisect_angle` on `run-1773528931`
- active rung is rung 5, with fresh exact red slice
  `miniwob_catalog_chase_circle`
- exact sentinel `miniwob_catalog_read_table` is now closed on
  `run-1773530273`
- exact widening slice `miniwob_catalog_read_table_2` is now closed on
  `run-1773530865`
- exact `miniwob_catalog_chase_circle` is now the active MiniWoB red on
  authoritative run `run-1774281832`
- exact `miniwob_catalog_phone_book` is now parked as a second honest planner
  plateau inside the post-geometry frontier
- exact `miniwob_catalog_email_inbox` is now parked as a third honest planner
  plateau inside the post-geometry frontier
- exact `miniwob_catalog_stock_market` is now parked as an honest dynamic-page
  plateau inside the post-geometry frontier
- exact `miniwob_catalog_social_media` is now closed on `run-1774201441`
- `miniwob_catalog_button_delay` is now a retained shared-fix validation target
  with a green direct bridge regression, not the current exact live frontier
- next benchmark move is to widen back to the full `catalog` audit after
  recording the `chase_circle` plateau
- reason: fresh authoritative exact reruns show the model already selects the
  right first hover on `chase_circle`, so further looping on the same slice
  would only repeat the same startup-budget ceiling instead of advancing MiniWoB
  coverage

Current blocker:

- active integrated-live state:
  - `run-1774281832` is the current canonical red for
    `miniwob_catalog_chase_circle`: `inference_calls.json` shows exactly one
    provider-backed tool call,
    `browser__hover {"id":"grp_circ","duration_ms":10000}`, and
    `bridge_state.json` recorded `reward=0.8367`
  - `run-1774283163` is the latest exact rerun on the reverted harness path:
    it kept the same one-turn hover plan and stayed red at `reward=0.7948`
- smallest honest remaining integrated gap:
  - `infra_or_bridge_gap` is now active on `miniwob_catalog_chase_circle`:
    the live model already chooses the correct first action, but immediate
    episode start plus first-step startup budget leave the full-duration hover
    short of the pass floor
- retained shared fix:
  - `miniwob_catalog_button_delay` is now a closed retained timed-sequence
    validation target: `run-1774288656` proved the shared ordered-click
    primitive, timed pending signal, and widened click-follow-up contract live
    with `reward=1.0`, while the direct MiniWoB bridge regression remains green
- retained plateau:
  - `miniwob_catalog_bisect_angle` stays classified as `planner_gap` after the
    older canonical run `run-1773528931` and the fresh 2026-03-22 reruns
    `run-1774227028`, `run-1774227554`, `run-1774227660`, and
    `run-1774227847`; reopening it again now would require a broader planner
    compliance improvement rather than more slice-local geometry tweaks
- retained plateau:
  - `miniwob_catalog_phone_book` and `miniwob_catalog_email_inbox` stay parked
    as broader planner plateaus after their latest authoritative live reds
- retained plateau:
  - `miniwob_catalog_stock_market` stays parked as a dynamic-page
    observation / recovery plateau after `run-1773542003`
- next required proof:
  - rerun the full MiniWoB `catalog` audit with
    `COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`
  - collapse back to the next exact red from fresh widened provider-backed
    evidence before switching benchmarks

Decision rule:

- keep rung 4 recorded as honestly plateaued unless new non-benchmark evidence
  exposes a shared planner improvement candidate
- keep the parked MiniWoB plateaus parked unless a broader shared planner or
  observation hypothesis appears
- keep `miniwob_catalog_chase_circle` recorded as a timed-hover plateau unless a
  broader startup-budget fix emerges from widened MiniWoB evidence
- only after the MiniWoB integrated suite is honestly exhausted again should
  the next benchmark iteration move to OSWorld preflight

## Rolling Window

Keep only the context needed for the next agent to continue correctly.

Latest authoritative closures:

- `run-1773498002` closes full cumulative `stress` at judged live `19/19`
  with provider-backed inference and full artifacts present
- `run-1773530273` closes rung 5 exact sentinel
  `miniwob_catalog_read_table` at judged live `1/1` with provider-backed
  inference, full artifacts, and `2` provider calls on `gpt-4o`
- `run-1773530865` closes rung 5 exact widening slice
  `miniwob_catalog_read_table_2` at judged live `1/1` with provider-backed
  inference, full artifacts, and `4` provider calls on `gpt-4o`
- `run-1773536893` moved `miniwob_catalog_phone_book` past the duplicate
  snapshot failure and exposed a shared click-verification gap on the stable
  paginator link `lnk_443422`
- `run-1773537341` proved the shared click-verification fix worked strongly
  enough to change the failure mode; the exact slice then stayed red because
  the planner clicked the wrong grounded contact link after a false recovery
  path
- `run-1773537614` is the canonical phone-book plateau: provider-backed
  inference, full artifacts, `12` provider calls on `gpt-4o`, and repeated
  `TargetNotFound` retries on hallucinated id `lnk_deena_address` despite the
  visible paginator and shared grounding guidance
- `run-1773539581` is the canonical email-inbox plateau: provider-backed
  inference, full artifacts, `27` provider calls on `gpt-4o`, and repeated
  planner drift between the broad inbox container, close-email navigation, and
  raw-id/text search retries even after shared mailbox-intent, icon
  observation, raw-id summary, and action-label planner fixes
- `run-1773542003` is the canonical stock-market plateau: provider-backed
  inference, full artifacts, `4` provider calls on `gpt-4o`, and a live bridge
  state that reached `Stock price: $59.00` against target `$59.60` while the
  agent still failed on a post-wait `browser__snapshot`, leaving a shared
  dynamic-page observation / recovery plateau rather than a planner-only miss
- `run-1774201441` is the canonical social-media closure: provider-backed
  inference, full artifacts, `1` provider call on `gpt-4o`, and a direct
  `browser__click_element` on surfaced control `btn_reply_a774a6`, which
  verified through selector `#area > div:nth-of-type(3) > div:nth-of-type(3) >
  span:nth-of-type(1)` for the target `@olin` row
- `run-1774281832` is the current canonical `chase_circle` red:
  provider-backed inference, full artifacts, `1` provider call on `gpt-4o`,
  and the right one-turn action
  `browser__hover {"id":"grp_circ","duration_ms":10000}`. The executor tracked
  selector `#circ` for the full hover and still finished at `reward=0.8367`,
  leaving a startup-budget plateau instead of a planner miss
- `run-1774283163` is the latest exact revalidation on the reverted harness
  path: provider-backed inference, full artifacts, `1` provider call on
  `gpt-4o`, the same one-turn hover plan, and a lower `reward=0.7948`, which
  strengthens the plateau classification
- `computer_use_suite::harness::tests::timed_ordered_click_sequence_solves_button_delay_directly`
  now passes locally against `/tmp/miniwob-plusplus`, proving the timed
  ordered-click primitive solves `button-delay` at the bridge/runtime layer
- `computer_use_suite::harness::tests::ordered_click_batch_solves_click_button_sequence_directly`
  now passes locally against `/tmp/miniwob-plusplus`, proving the generalized
  low-latency ordered-click executor also solves `click-button-sequence` at the
  bridge/runtime layer
- `run-1774290416` is the canonical `click_button_sequence` closure:
  provider-backed inference, full artifacts, `1` provider call on `gpt-4o`,
  and a one-turn grounded start-gate click whose nested ordered click batch
  closed the slice at `raw_reward=1.0`
- `run-1774227028`, `run-1774227554`, `run-1774227660`, and `run-1774227847`
  are the current `bisect_angle` revalidation evidence on today’s code:
  provider-backed inference with full artifacts kept the slice red even after
  shared screenshot grounding, decimal SVG probes, synthetic-click geometry
  reverification, offset-aware correction, and explicit correction-call
  prompting. Those runs sharpen the slice into an honest planner-compliance
  plateau rather than a missing bridge primitive.

Retained shared fixes that matter for future regressions:

- browser-launch instability is closed on the widened path:
  `run-1773489982` re-closed the first launch-blocked exact slice and
  `run-1773490053` kept full `core` green again
- MiniWoB turnover bridge accounting is closed:
  `run-1773487291` preserved terminal reward / termination across immediate
  next-episode turnover strongly enough for authoritative judgment
- visible-target grounding on tabbed / collapsible pages is closed and widened:
  `run-1773494132` and `run-1773497922` re-closed exact slices, and
  `run-1773498002` kept them green in-family
- ranked-result pagination plus planner handoff is closed and widened:
  `run-1773497374` re-closed `miniwob_search_engine_stress`, and
  `run-1773498002` kept it green in-family
- autocomplete unresolved-state recovery is closed on the widened path:
  `run-1773489181` landed the generic `ArrowDown` then `Enter` reduction, and
  later widened reruns kept the reopened `core` family green
- selector-targeted browser selection / clipboard affordances plus conditional
  scroll-target hints are now grounded for catalog-style text transfer:
  `run-1773525481` closed `miniwob_catalog_copy_paste` in four steps on live
  inference after exposing selector-targeted select/paste affordances and
  removing imperative scroll-click guidance from generic browser hints
- post-click MiniWoB SVG targets now remain visible to the agent on the
  generic observation surface:
  `run-1773525547` exposed that `miniwob_catalog_ascending_numbers` replaced
  clicked SVG text with clickable `<rect data-index=...>` targets that DOM
  fallback snapshots dropped; `run-1773527672` re-closed after preserving
  visible SVG leaf targets and surfacing stable shape metadata through the
  accessibility XML
- generic unknown-task `catalog` survey recipes now get a shared `8`-step
  budget instead of `4`, preventing false reds on longer survey-only tasks
  without introducing task-specific exceptions; `run-1773527672` is the
  authoritative closure that proved the budget was sufficient for
  `miniwob_catalog_ascending_numbers`
- headless browser follow-ups now expose a shared direct coordinate-click
  primitive for canvas / SVG / blank-region interaction:
  `run-1773528784` proved `miniwob_catalog_bisect_angle` could select
  `browser__synthetic_click` under live inference after surfacing the existing
  primitive in the DomHeadless browser tool set
- SVG shape nodes now surface explicit viewport centers in the XML:
  `run-1773528931` proved the agent switched from bounding-box-edge clicks to
  exact point-center clicks after surfacing `center_x` / `center_y` for shared
  SVG shape nodes
- built-in MiniWoB `catalog` is now honestly plateaued on a geometry planner
  gap rather than a missing tool surface:
  `run-1773528931` remains the canonical proof that `miniwob_catalog_bisect_angle`
  still fails after shared pointer and observation fixes, so future work there
  must come from a broader planner improvement rather than more benchmark-local
  iteration
- duplicate immediate browser snapshot replays no longer masquerade as safe
  duplicate success:
  the shared duplicate-execution guard now turns repeated
  `browser__snapshot` replays into `NoEffectAfterAction`, preserving noop-safe
  behavior for other non-command duplicates while exposing real verification
  failures for recovery
- duplicate-snapshot incident recovery now sees the same latest
  snapshot-aware pending browser state that main cognition sees:
  the shared incident planner path now hydrates pending browser state from the
  latest snapshot-aware helper first, then falls back to history-only context,
  so recovery prompts can reuse grounded ids like `lnk_443422` instead of
  drifting into blind inspection loops
- blocked completion / chat terminalization now emits real
  `ERROR_CLASS=NoEffectAfterAction` failures when unresolved browser work
  remains instead of recording a successful no-op duplicate completion
- stable link clicks that keep the same semantic id now count as successful
  when surrounding named page content changes materially:
  `run-1773536893` exposed the need on MiniWoB pagination, and later exact
  reruns moved the slice on to planner-only failures
- browser operating rules now explicitly forbid synthesized
  `browser__click_element` ids and instruct the planner to treat
  instruction-only `browser__find_text` hits as navigation evidence rather
  than target visibility; `run-1773537614` still remained red, so the current
  `phone_book` gap is parked as planner-limited
- explicit browser-only goals now suppress mailbox-connector prompt injection
  and execution-time mailbox gating; `run-1773538055` proved the fix by moving
  `miniwob_catalog_email_inbox` from mailbox terminalization to browser-side
  planner behavior
- icon-only DOM-fallback browser controls now surface semantic names plus
  `dom_clickable=true`, and compact browser prompt summaries now lead with raw
  semantic ids instead of tag-prefixed ids; `run-1773538994` and
  `run-1773539367` proved those shared fixes by moving `email_inbox` from
  instruction-token and prompt-format failures to nearby-control planner drift
- browser recovery and queue hardening now turn `stock_market` deadlocks into
  authoritative live reds instead of stale-browser hangs: bounded CDP health
  probes, active/retrieval URL rehydration across browser restarts, bounded
  current-browser observation fetches, browser queue-tool timeouts, and fixed
  `browser__wait {ms}` without pre-wait page reacquisition together moved the
  slice to a buyable live page state on `run-1773542003`
- DOM-fallback row-action strips now surface semantic names, button roles, and
  selectors for icon-only controls, and pending exact-text targeting now
  prefers actionable controls over instruction-copy tokens; `run-1774201441`
  proved the shared fix by closing `miniwob_catalog_social_media` in one live
  provider-backed step
- browser click verification now starts probing immediately after dispatch,
  uses a shorter settle schedule, and compacts verbose
  `browser__click_element` receipts before they return to model context
- timed ordered-click execution plus dedicated timed-sequence pending guidance
  now solve `miniwob_catalog_button_delay` directly in the MiniWoB bridge
  regression without introducing benchmark-local routing
- ordered `browser__click_element` batches without explicit delay now reuse the
  same low-latency intermediate dispatch path as timed sequences, and direct
  bridge coverage proves that shared executor also closes
  `miniwob_catalog_click_button_sequence`
- OSWorld bridge preflight now distinguishes a truly missing `desktop_env`
  source/package from a discoverable source tree whose import is only blocked
  by a transitive dependency like `gymnasium`, so the blocker chain no longer
  duplicates the same missing Python requirement under two separate headings
- interrupted widened family runs can leave an orphaned Chromium runner profile
  that causes zero-call launch failures on exact reruns; `run-1773528640` and
  `run-1773528708` are non-authoritative infra-blocked reruns and must not be
  mistaken for benchmark evidence

Retention policy:

- keep the active rung
- keep the latest authoritative closure for each closed family
- keep only dormant gap notes that could plausibly reopen on the next rung
- remove date logs, narrative iteration history, and superseded local notes
- current in-flight handoff target is the widened MiniWoB `catalog` audit;
  `miniwob_catalog_chase_circle` is recorded as the current exact plateau, and
  OSWorld stays queued behind the integrated MiniWoB suite

## Benchmark Snapshot

| Family / rung | Status | Authoritative result | Command shape | Artifact root |
| --- | --- | --- | --- | --- |
| full `smoke` | passed | `run-1773452927`: judged live `8/8` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=smoke ...` | `run-1773452927/agent` |
| full `core` audit | passed | `run-1773490053`: judged live `17/17` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=core ...` | `run-1773490053/agent` |
| full `workflow` | passed | `run-1773456913`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow ...` | `run-1773456913/agent` |
| full `workflow_rich` | passed | `run-1773469571`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_rich ...` | `run-1773469571/agent` |
| full `workflow_audit` | passed | `run-1773469870`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_audit ...` | `run-1773469870/agent` |
| full `workflow_mutation` | passed | `run-1773479507`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_mutation ...` | `run-1773479507/agent` |
| full `workflow_reorder` | passed | `run-1773483313`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_reorder ...` | `run-1773483313/agent` |
| full `stress` audit | passed | `run-1773498002`: judged live `19/19` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=stress ...` | `run-1773498002/agent` |
| catalog sentinel: `miniwob_catalog_copy_paste` | passed | `run-1773525481`: judged live `1/1` with provider-backed inference, `4` provider calls, and full artifacts | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_copy_paste cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773525481/agent` |
| full `catalog` audit | red, collapsed | `run-1773527869`: widened live audit reached the next post-closure family red in order, `miniwob_catalog_bisect_angle`; `miniwob_catalog_ascending_numbers` had already stayed green and the red slice had non-zero provider calls plus authoritative artifacts before collapsing back to exact-first | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773527869/agent` |
| catalog exact frontier: `miniwob_catalog_chase_circle` | red, plateaued | `run-1774281832`: case-level live red with provider-backed inference, full artifacts, and `1` provider call on `gpt-4o`; the model chose `browser__hover {"id":"grp_circ","duration_ms":10000}` immediately, tracked selector `#circ` for the full hover, and still graded `reward=0.8367`. Revalidation `run-1774283163` kept the same one-turn hover path red at `reward=0.7948` after reverting a losing harness timing experiment, leaving an honest startup-budget plateau. | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_chase_circle cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1774281832/agent/miniwob_catalog_chase_circle` |
| catalog exact red slice: `miniwob_catalog_bisect_angle` | red, plateaued | `run-1773528931`: judged live red with provider-backed inference, full artifacts, and `3` provider calls; after shared headless coordinate-click and SVG-center surfacing, the agent clicked visible point centers then `btn_submit` for `raw_reward=-1.0`, leaving an honest planner gap | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_bisect_angle cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773528931/agent/miniwob_catalog_bisect_angle` |
| rung 5 sentinel: `miniwob_catalog_read_table` | passed | `run-1773530273`: judged live `1/1` with provider-backed inference, full artifacts, and `2` provider calls on `gpt-4o`; the agent read `Language -> French`, typed the grounded value, and clicked submit for `reward=0.522` | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_read_table cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773530273/agent/miniwob_catalog_read_table` |
| rung 5 exact widening slice: `miniwob_catalog_read_table_2` | passed | `run-1773530865`: judged live `1/1` with provider-backed inference, full artifacts, and `4` provider calls on `gpt-4o`; the agent read both requested mappings, typed `Alvinia` and `Faroe Islands`, then clicked submit for `reward=0.621` | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_read_table_2 cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773530865/agent/miniwob_catalog_read_table_2` |
| rung 5 exact slice: `miniwob_catalog_phone_book` | red, plateaued | `run-1773537614`: judged live red with provider-backed inference, full artifacts, and `12` provider calls on `gpt-4o`; after shared duplicate-snapshot, pending-state, click-postcondition, blocked-completion, and grounding-prompt fixes, the agent still invented nonexistent ids like `lnk_deena_address` and never acted on visible paginator `lnk_443422`, leaving an honest planner plateau | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_phone_book cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773537614/agent/miniwob_catalog_phone_book` |
| rung 5 exact slice: `miniwob_catalog_email_inbox` | red, plateaued | `run-1773539581`: judged live red with provider-backed inference, full artifacts, and `27` provider calls on `gpt-4o`; after shared mailbox-intent suppression, icon-control observation surfacing, raw-id prompt compaction, and action-label disambiguation, the planner still oscillated between the broad inbox container, `close email`, and text-search retries instead of completing the requested `trash` action | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_email_inbox cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773539581/agent/miniwob_catalog_email_inbox` |
| rung 5 exact slice: `miniwob_catalog_stock_market` | red, plateaued | `run-1773542003`: judged live red with provider-backed inference, full artifacts, and `4` provider calls on `gpt-4o`; after shared browser recovery and wait/runtime fixes, the bridge reached `Stock price: $59.00` against target `$59.60`, but the agent still failed on the post-wait `browser__snapshot`, leaving an honest dynamic-page observation / recovery plateau | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_stock_market cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1773542003/agent/miniwob_catalog_stock_market` |
| rung 5 exact slice: `miniwob_catalog_social_media` | passed | `run-1774201441`: judged live `1/1` with provider-backed inference, full artifacts, and `1` provider call on `gpt-4o`; after shared DOM-fallback row-action surfacing and actionable-target ranking fixes, the agent clicked grounded control `btn_reply_a774a6` for the `@olin` row and closed the slice | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_social_media cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1774201441/agent/miniwob_catalog_social_media` |
| retained validation target: `miniwob_catalog_button_delay` | passed | `run-1774288656`: judged live `1/1` with provider-backed inference, full artifacts, and `1` provider call on `gpt-4o`; after widening generic click follow-ups to admit nested `browser__wait`, the model emitted one ordered `browser__click_element` on `btn_one` then `btn_two` with `delay_ms_between_ids=2000` and closed the slice at `reward=1.0` | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_button_delay cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1774288656/agent/miniwob_catalog_button_delay` |
| retained validation target: `miniwob_catalog_click_button_sequence` | passed | `run-1774290416`: judged live `1/1` with provider-backed inference, full artifacts, and `1` provider call on `gpt-4o`; the model clicked `grp_start` and nested an ordered `browser__click_element` batch on `btn_one` then `btn_two` with `delay_ms_between_ids=100`, and the generalized low-latency ordered-click executor closed the slice at `raw_reward=1.0` | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_click_button_sequence cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | `run-1774290416/agent/miniwob_catalog_click_button_sequence` |

## Capability Gap Matrix

Only gaps exposed by live suite runs are active.

| Gap class | Current status | Handling |
| --- | --- | --- |
| `missing_pointer_primitive` | dormant | `run-1773528784` proved shared headless `browser__synthetic_click` exposure was enough for live agent selection on `miniwob_catalog_bisect_angle`; reopen only on fresh live evidence |
| `missing_selection_primitive` | dormant | next rung is designed to probe this honestly via `catalog`; reopen only on fresh live evidence |
| `missing_keyboard_primitive` | dormant | reopen only on fresh live evidence |
| `missing_clipboard_primitive` | dormant | next rung is designed to probe this honestly via `catalog`; reopen only on fresh live evidence |
| `observation_gap` | plateaued | `run-1773542003` still leaves `miniwob_catalog_stock_market` without a usable post-wait semantic view even after shared browser recovery hardening; `run-1774201441` closed the former `social_media` observation slice after shared DOM-fallback row-action surfacing and actionable-target ranking fixes |
| `verification_gap` | dormant | `run-1774288656` closed the former `miniwob_catalog_button_delay` timing / sequencing gap live after widening generic click follow-ups to admit grounded `browser__wait`, and `run-1774290416` closed `miniwob_catalog_click_button_sequence` after generalizing the same low-latency ordered-click executor to undelayed batches; both direct ordered-click regressions stay green, so reopen only on fresh live evidence. |
| `planner_gap` | plateaued | `run-1773528931` leaves `miniwob_catalog_bisect_angle` red after shared pointer and SVG-center fixes, `run-1773537614` leaves `miniwob_catalog_phone_book` red after shared verification and planner-prompt fixes, and `run-1773539581` leaves `miniwob_catalog_email_inbox` red after shared mailbox-intent, icon observation, raw-id prompt, and action-label fixes; all three slices now require a broader planner improvement rather than more slice-local iteration |
| `recovery_gap` | dormant | workflow mutation and reorder closures keep the last recovery reductions green |
| `infra_or_bridge_gap` | active | `run-1774281832` and `run-1774283163` make `miniwob_catalog_chase_circle` the current startup-budget / bridge-timing gap: the live model already chooses the correct one-turn hover, but immediate episode start plus first-step latency cap reward below the pass floor even with full-duration tracking. |

## Benchmark Escalation Ladder

1. Closed MiniWoB ladder
   Status: passed.
   Scope:
   - full `smoke`
   - full `core`
   - full cumulative `stress`
   Canonical closures:
   - `smoke`: `run-1773452927`
   - `core`: `run-1773490053`
   - `stress`: `run-1773498002`
   Retained meaning:
   - browser-core DOM interpretation is live-proven on the widened MiniWoB path
   - current MiniWoB follow-on work should target unproven `catalog` surfaces,
     not rerun closed smoke/core/stress families first

2. Closed workflow ladder
   Status: passed.
   Scope:
   - `workflow`
   - `workflow_rich`
   - `workflow_audit`
   - `workflow_mutation`
   - `workflow_reorder`
   Canonical closures:
   - `workflow`: `run-1773456913`
   - `workflow_rich`: `run-1773469571`
   - `workflow_audit`: `run-1773469870`
   - `workflow_mutation`: `run-1773479507`
   - `workflow_reorder`: `run-1773483313`
   Retained meaning:
   - browser-only ticket-routing / verification / audit / mutation / queue
     reorder flows are live-proven on the authoritative harness

3. Catalog selection / clipboard sentinel
   Status: passed.
   Objective:
   - stay on MiniWoB after `stress` closure and start the built-in `catalog`
     family with exact live sentinel `miniwob_catalog_copy_paste`
   Why this sentinel:
   - it is the smallest honest built-in `catalog` case that materially
     exercises the selection / clipboard tool surface under live
     provider-backed inference
   Exact command:
   - `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_copy_paste cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`
   First-pass classification rule:
   - if red, classify the smallest honest shared gap and fix only that
   - if green, record artifacts and widen only to the next catalog rung
   Canonical closure:
   - `run-1773525481`: judged live `1/1` with provider-backed inference,
     `4` provider calls, and full artifacts
   Exit criterion:
   - closed

4. Full MiniWoB catalog mastery
   Status: plateaued.
   Objective:
   - after rung 3 closes, continue exact-first through built-in MiniWoB
     `catalog` until the family reaches live parity or an honest plateau
   Immediate widening order:
   - exact `miniwob_catalog_copy_paste`
   - widened `catalog` audit
   - collapsed exact red slice `miniwob_catalog_chase_circle`
   - rerun exact `miniwob_catalog_chase_circle` after shared startup-budget
     observations and prompt-observation warmup work
   - widen back to full `catalog`
   - collapse to exact `miniwob_catalog_bisect_angle`
   - rerun exact `miniwob_catalog_bisect_angle` after shared headless
     coordinate-click exposure
   - rerun exact `miniwob_catalog_bisect_angle` after shared SVG-center
     observation surfacing
   Canonical plateau:
   - `run-1773528931`: honest planner plateau on
     `miniwob_catalog_bisect_angle`; further work there now requires a broader
     shared planner improvement, not more slice-local iteration
   Exit criterion:
   - plateau reached and recorded

5. Post-catalog frontier choice
   Status: exact plateau recorded; widen back to audit.
   Objective:
   - exhaust MiniWoB before switching benchmarks by recording the current
     `chase_circle` plateau honestly, then rerunning the full `catalog` audit
   Active exact slice:
   - `miniwob_catalog_chase_circle`
   Fresh canonical red:
   - `run-1774281832`: provider-backed inference, full artifacts, and `1`
     provider call; the live model immediately chose
     `browser__hover {"id":"grp_circ","duration_ms":10000}`, tracked
     selector `#circ` for the full hover, and still graded `reward=0.8367`
   Revalidation:
   - `run-1774283163`: after reverting a losing harness timing experiment, the
     same one-turn hover path stayed red at `reward=0.7948`, confirming the
     slice is a startup-budget plateau rather than a planner-intent miss
   Landed shared follow-up:
   - prompt-observation warmup can now cache grounded targets that coexist with
     the MiniWoB start gate
   - losing harness timing reorder was reverted after `run-1774282952` made the
     exact slice worse
   - timed ordered-click execution and timed pending guidance remain retained
     shared fixes from the earlier `button_delay` frontier
   Exit criterion:
   - rerun full `catalog`, collapse the next exact red from fresh widened
     evidence, and only then move the next benchmark loop to bridge-alpha
     readiness

## Iteration Update Protocol

For every iteration:

1. Update `Status`, `Rolling Window`, `Benchmark Snapshot`, and the active rung
   first.
2. Stay on the active family until it reaches parity, plateaus, or hard-blocks.
3. Keep the inner loop simple:
   - run the current sentinel or exact failing case
   - inspect artifacts
   - classify the smallest honest shared gap
   - implement only a shared fix
   - rerun the exact same live slice
   - only then widen
4. Treat cumulative sets (`core`, `stress`, `catalog`) as audit rungs, not the
   per-fix dev loop.
5. Record for every authoritative run:
   - exact command
   - runtime / provider / model
   - task set and case ids
   - artifact root
   - judged outcome
   - smallest honest gap class
   - whether the run was diagnostic or authoritative
6. Prefer generic fixes over benchmark-local recipes.
7. Add deterministic coverage only when a live failure first proves a reusable
   gap.
8. When a rung closes, immediately define the next rung in this file.
9. Keep this file under `500` lines by preserving only the rolling window and
   canonical closure references.

## Current Next Move

MiniWoB is still the active integrated suite. The next honest benchmark move is
to widen back to the full `catalog` audit on the current code:

```bash
COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus \
COMPUTER_USE_SUITE_MODE=agent \
COMPUTER_USE_SUITE_AGENT_BACKEND=live_http \
COMPUTER_USE_SUITE_TASK_SET=catalog \
cargo test -p ioi-cli --test computer_use_suite_e2e \
  computer_use_suite_from_env -- --ignored --exact --nocapture
```
