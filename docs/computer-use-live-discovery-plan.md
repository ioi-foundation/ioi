# Computer-Use Live Discovery Plan

This file is the single authoritative living spec for benchmark-driven
computer-use improvement in this repo.

Scope:

- active family: `crates/cli/tests/computer_use_suite`
- active objective: climb the suite from easiest live tasks to hardest live
  tasks using the repo-real agent stack
- downstream objective: after this family reaches parity, plateaus, or
  hard-blocks, apply the same method to the next suite family

Method invariants:

- live-inference-first
- benchmark-driven
- no ad hoc heuristics
- no benchmark-conditioned routing
- no cheating against judges
- shared fixes only: runtime, observation, verification, recovery, bridge, or
  generic tool surfaces
- exact failing live slice first, broader family second
- cumulative sets are audit rungs, not the inner-loop dev target

## Status

Current frontier:

- `workflow_reorder` is now closed live: exact rerun `run-1773483141` passes
  judged `1/1`, and full-family rerun `run-1773483313` passes judged `2/2`
  with provider-backed inference and full live artifacts present
- exact stress sentinel `run-1773484611` now passes judged live `1/1` with
  provider-backed inference (`live_http`, `gpt-4o`, 5 calls) and full live
  artifacts present. The shared visible-target handoff now lands on the
  authoritative live path strongly enough for the model to click the exact
  visible target after section exploration instead of the surrounding panel
- cumulative `stress` audit `run-1773484641` then failed judged live `15/19`
  with provider-backed inference and full live artifacts present. The reopened
  cases are `miniwob_click_option_core` (`verification_gap`,
  `TargetNotFound`, 13 calls), `miniwob_click_checkboxes_core`
  (`verification_gap`, `TargetNotFound`, 14 calls),
  `miniwob_click_checkboxes_transfer_core` (`planner_gap`, `task_incomplete`,
  11 calls), and `miniwob_search_engine_stress` (`planner_gap`,
  `NoEffectAfterAction`, 14 calls)
- because cumulative sets are audit rungs rather than the inner-loop dev
  target, the active frontier now drops to the first failing exact slice in
  audit order: `miniwob_click_option_core`
- exact rerun `run-1773487291` re-closed
  `miniwob_click_option_core` judged live with provider-backed inference
  (`live_http`, `gpt-4o`, 2 calls) and full live artifacts present
- full cumulative `core` rerun `run-1773487386` then passed judged live
  `16/17` with provider-backed inference and full live artifacts present
- exact rerun `run-1773489181` closed
  `miniwob_use_autocomplete_smoke` judged live with provider-backed inference
  (`live_http`, `gpt-4o`, 4 calls) and full live artifacts present
- full cumulative `core` rerun `run-1773489311` has now finished judged live
  `13/17` with provider-backed inference and full live artifacts present on
  the passing cases. The family rerun reopens four harness-blocked cases, and
  the first exact red slice in family order is `miniwob_click_tab_smoke`
- the smallest honest current gap has tightened from planner behavior back to
  `infra_or_bridge_gap`: `run-1773489311` records repeated agent-mode browser
  launch failures where Chromium exits before the CDP websocket URL is
  resolved. The same shared launch-path miss has already reopened
  `miniwob_scroll_text_direction_smoke`, `miniwob_click_checkboxes_core`, and
  `miniwob_focus_text_2_core` during the same family run
- the active inner-loop target is now the authoritative exact live rerun of
  `miniwob_click_tab_smoke`; only after that exact slice recloses should the
  family rerun resume, and only after full `core` is green again should work
  return to the parked cumulative `stress` audit
- exact rerun `run-1773489982` now re-closes
  `miniwob_click_tab_smoke` judged live `1/1` with provider-backed inference
  (`live_http`, `gpt-4o`, 1 call) and full live artifacts present
- full cumulative `core` rerun `run-1773490053` now passes judged live
  `17/17` with provider-backed inference and full live artifacts present
- the shared launch-instability rung is now re-closed on the widened family:
  all four cases that were harness-blocked in `run-1773489311`
  (`miniwob_click_tab_smoke`, `miniwob_scroll_text_direction_smoke`,
  `miniwob_click_checkboxes_core`, and `miniwob_focus_text_2_core`) now pass
  again on the authoritative live path
- the current frontier returns immediately to the parked cumulative `stress`
  audit
- cumulative `stress` rerun `run-1773490463` is now in flight on the
  authoritative live path. It has already re-cleared every previously reopened
  `core`-derived case through `miniwob_click_button_sequence_core` without
  reopening the prior `infra_or_bridge_gap`, `verification_gap`, or
  `planner_gap` branches from `run-1773484641`
- authoritative exact rerun `run-1773486459` stayed red on
  `miniwob_click_option_core`, but it closed the smaller bridge issue live:
  `agent__complete` was present in the tool list and the model ultimately
  called it successfully
- authoritative exact rerun `run-1773486774` then stayed red again, but it
  also closed the planner miss live: the agent now executes the correct
  three-step path `radio_tecslmn` -> `btn_submit` -> `agent__complete`, and
  the final provider grading call in `inference_calls.json` scores the task as
  achieved. The remaining miss is now a smaller `infra_or_bridge_gap`: the
  persisted `bridge_state.json` was sampled after episode turnover had already
  reset the structured MiniWoB fields to `reward=0`, `raw_reward=0`, and
  `terminated=false`, even though the same DOM snapshot still shows
  `Last reward: 0.62` and `Episodes done: 1`
- latest exact `core` reduction is now scoped as a bridge-accounting fix:
  preserve terminal MiniWoB reward / termination strongly enough across the
  immediate next-episode turnover so authoritative suite runs do not lose the
  successful episode before final judgment
- latest exact closure `run-1773487291` proves that fix lands on the
  authoritative live path: even though the browser DOM had already turned over
  to the next episode, the persisted bridge state kept the completed episode's
  `raw_reward=1.0`, `terminated=true`, and original task brief, so the exact
  live slice passes again and the frontier widens to full `core`
- latest family rerun `run-1773487386` proves the next remaining live miss is
  back in planner behavior: `miniwob_use_autocomplete_smoke` is the only red
  case left in cumulative `core`, with `agent_state.json` marked completed and
  the provider grading call scoring the run `1.0`, but the benchmark bridge
  state still shows an unresolved autocomplete input (`value=\"Poland\"`,
  `Episodes done: 0`, `reward=0`). The active move collapses to that exact
  slice before widening again
- authoritative exact rerun `run-1773487838` kept that same exact slice red:
  the live model again typed `Poland`, clicked `btn_submit`, and called
  `agent__complete` while the autocomplete widget was still unresolved. The
  prompt already included RECENT PENDING BROWSER STATE, but it was too generic
  and competed with a submit-click RECENT SUCCESS SIGNAL
- exact rerun `run-1773488542` proved the first shared reduction landed on the
  live path: the prompt now names `inp_tags`, `Poland`, and a concrete
  follow-up, and the live model follows it far enough to press
  `browser__key` `Enter` before submitting. That run stayed red because the
  key result still carried active autocomplete state, so the remaining miss
  tightened again from generic autocomplete cueing to unresolved-enter
  recovery
- latest exact closure `run-1773489181` proves the refined recovery lands on
  the authoritative live path: the prompt now directs `ArrowDown` then
  `Enter` unless there is grounded evidence of an already highlighted
  candidate, and the live model closes the slice with the exact four-step path
  `#tags` -> `ArrowDown` -> `Enter` -> `btn_submit`
- retained shared reduction from workflow-reorder:
  refreshed-queue stale guidance is suppressed once `btn_apply_filters` has
  already been observed, and reordered-queue handoff can fall back to the
  latest richer queue snapshot in history when the current snapshot is too thin
  to surface the distractor history link directly
- retained shared reduction from stress:
  exact visible-target grounding is now strong enough on tabbed/collapsible
  pages for the live model to click the concrete target element directly once
  that target text is visibly present
- only return to the full cumulative `stress` audit after the reopened exact
  `core` slice is re-closed and the full `core` family is green again

Current blocker:

- no active hard blocker on the current rung
- latest workflow-reorder exact closure:
  `run-1773483141` passes judged live on
  `workflow_stale_queue_reorder_billing_review` with provider-backed inference,
  20 provider calls, and full live artifacts present. The richer-snapshot
  fallback now lands on the authoritative live path: after confirmation the
  agent returns to the queue, switches `inp_queue_sort` to `Recently Updated`,
  refreshes with `btn_apply_filters`, and then opens distractor history
  `lnk_history_807ebf` instead of reopening `T-318`
- latest workflow-reorder family closure:
  `run-1773483313` passed judged live `2/2` on full `workflow_reorder` with
  provider-backed inference and full live artifacts present. Both reorder
  cases now close together on the authoritative live harness, so rung 9 is
  complete and the frontier advances to stress
- current blocker:
  no hard blocker. Exact rerun `run-1773489982` and full cumulative `core`
  rerun `run-1773490053` close the shared browser-launch instability on the
  authoritative live harness, so the active move is the in-flight full
  cumulative `stress` audit `run-1773490463`. If that audit reopens, collapse
  immediately to the first exact red slice in family order
- latest exact `core` local proof:
  the sticky terminal-state bridge fix is now live-proven by
  `run-1773487291`, and full cumulative `core` has already been rerun. The
  next required proof is the authoritative exact rerun of
  `miniwob_use_autocomplete_smoke`
- latest stress exact closure:
  `run-1773484611` passed judged live on
  `miniwob_click_collapsible_2_stress` with provider-backed inference
  (`live_http`, `gpt-4o`, 5 calls) and full live artifacts present, including
  non-zero `inference_calls.json` and `inference_trace.json`. The new exact
  target-click pending cue now grounds the visible target element strongly
  enough for the live model to convert section exploration into the final click
- latest cumulative stress frontier:
  `run-1773484641` failed judged live `15/19` on full cumulative `stress`
  with provider-backed inference and full live artifacts present. The first
  failing case in audit order is `miniwob_click_option_core`, followed by
  `miniwob_click_checkboxes_core`,
  `miniwob_click_checkboxes_transfer_core`, and
  `miniwob_search_engine_stress`; therefore the active move collapses to the
  exact `miniwob_click_option_core` live rerun rather than more cumulative
  widening
- latest rung closure:
  `run-1773483141` passed judged live on
  `workflow_stale_queue_reorder_billing_review` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`) and full live artifacts present,
  including non-zero `inference_calls.json` and `inference_trace.json`. The
  landed richer-snapshot fallback now holds on the live path: after queue
  refresh the model hands off cleanly to distractor history instead of
  reopening `T-318`
- latest family closure:
  `run-1773483313` passed judged live `2/2` on full `workflow_reorder` with
  provider-backed inference and full live artifacts present. Both reorder
  cases now close on the authoritative live harness, so the active frontier
  moves forward to the stress sentinel
- latest exact mutation variance candidate:
  `run-1773475880` failed judged live on
  `workflow_mutation_isolation_billing_review` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`), but it recorded only `1` provider call
  and never exercised the post-login or history frontier: the lone action was
  typing the username on the login page, after which the run idled back to a
  login-page workflow observation. Because the exact rerun never reached the
  new history-page mismatch cue and leaves `agent_state.json` still `Running`
  at step `1`, treat it as transient variance unless the same early stall
  reproduces on the next exact rerun
- latest exact mutation closure:
  `run-1773475037` passed judged live on
  `workflow_mutation_isolation_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 30 calls) and full live artifacts
  present, including `agent_state.json`, `inference_trace.json`, and
  `inference_calls.json`. The stricter viewed-history detector now stops queue
  snapshots with visible history links from suppressing cross-item follow-up,
  and the live action trace closes the exact slice by returning from `T-215`
  history to the queue and then opening `T-204` history via
  `lnk_history_4c23bd`
- latest exact mutation frontier:
  `run-1773474416` failed judged live on
  `workflow_mutation_isolation_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 30 calls) and full live artifacts
  present. The run gets through mutation, confirmation, `T-215` audit history,
  and one correct return to the queue, but then reopens `T-215` history and
  burns the remaining steps on repeated snapshots. Prompt inspection on the
  exact rerun shows the queue view after returning from history receives only a
  generic click-success cue, not the intended cross-item history follow-up
  cue. The shared cause is that history-follow-up detection still over-counts
  queue snapshots that merely contain history links, so the prompt fails to
  name `T-204` / `lnk_history_4c23bd` as the next grounded verification step.
  That shared detection fix is now landed and covered by focused prompt-history
  tests; the next move is the exact live rerun
- latest exact mutation variance candidate:
  `run-1773474910` failed judged live on
  `workflow_mutation_isolation_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 26 calls), but unlike `run-1773474416`
  it regressed much earlier: after sign-in it burned steps on aggregate
  `grp_login_divide_queue` clicks, then fell into recovery after a cognition
  timeout (`ERROR_CLASS=TimeoutOrHang`) while retrying `browser__snapshot`.
  Because this newest rerun never reached the post-history queue-return
  frontier and recorded `kernel_successes=0`, treat it as transient-vs-stable
  exact evidence. `run-1773475037` immediately re-closed the same exact slice,
  so keep `run-1773474910` only as transient variance unless the timeout path
  reproduces again
- latest exact mutation variance candidate:
  `run-1773477962` failed judged live on
  `workflow_mutation_isolation_billing_review` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 33 calls), but it regressed earlier than
  `run-1773478221`: after sign-in it burned recovery on repeated
  `grp_login_divide_queue` no-effect clicks, then after opening `T-318` it
  spent three repeated `browser__snapshot` calls before resuming form entry.
  The run never reached the review-confirmation or post-confirm queue-return
  frontier, so it does not yet validate or falsify the newer reduction.
  Treat it as transient exact variance unless the same queue-container /
  repeated-snapshot path reproduces on the next exact rerun
- latest exact mutation variance candidate:
  `run-1773478557` failed judged live on
  `workflow_mutation_isolation_billing_review` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 34 calls), but it again regressed earlier
  than `run-1773478221`: after sign-in it burned recovery on repeated
  `grp_login_divide_queue` no-effect clicks, then after opening `T-318` it
  consumed the remaining budget on form entry without reaching review,
  confirmation, or any history page. Because the run never exercised the new
  post-confirm queue-return cue and the suite reports `kernel_contract`
  `verification_gap` / `NoEffectAfterAction`, treat it as transient exact
  variance unless the same early queue-container path reproduces again
- latest full-family frontier:
  `run-1773475196` failed judged live `1/2` on full `workflow_mutation`
  with provider-backed inference and full live artifacts present. The first
  failing case in family order is
  `workflow_mutation_isolation_billing_review`, which recorded `4` provider
  calls and is now classified by the suite as `recovery_gap` with
  `TimeoutOrHang`, but the later exact reruns now tighten the smaller shared
  cause twice: `run-1773476023` lands the history-page mismatch cue and moves
  the frontier onto confirmation-page verification, while `run-1773476838`
  lands that confirmation reduction and moves the frontier again onto
  post-reopen draft recovery after `btn_reopen_ticket` succeeds;
  sibling case
  `workflow_mutation_isolation_network_ops` now passes judged live with `18`
  provider calls and full live artifacts present, so the active move
  collapses to the exact `billing_review` slice
- latest exact mutation frontier:
  `run-1773473228` failed judged live on
  `workflow_mutation_isolation_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 32 calls) and full live artifacts
  present. The run now clears sign-in, queue mutation, review, confirmation,
  queue return, and `T-215` history open; on ordinals `27-32` it lands on the
  `T-215` audit history page where the saved dispatch-update row is already
  visible in the snapshot, then burns the remaining steps on repeated
  `browser__snapshot` plus recovery scroll instead of converting that visible
  evidence into verification and continuing to the next required history check.
  Focused prompt-history reproduction proved the intended generic pending cue
  was over-length under `PENDING_BROWSER_STATE_MAX_CHARS`, so the actionable
  `` `lnk_queue` `` return step was truncated out before the model saw it
- latest full-family closure:
  `run-1773469870` passed `2/2` judged live on full `workflow_audit`; both
  cases recorded non-zero provider calls (`15`, `13`) and persisted
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`, so
  rung 7 is closed and the ladder advances to the workflow-mutation sentinel
- latest exact workflow-audit closure:
  `run-1773469772` passed judged live on
  `workflow_audit_history_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 15 calls) and full live artifacts
  present, so rung 7 now widens to the full `workflow_audit` family
- latest closed-family reference:
  `run-1773469571` passed `2/2` judged live on full `workflow_rich`; both
  cases recorded non-zero provider calls (`17`, `15`) and persisted
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`
- latest exact rerun:
  `run-1773469438` passed judged live on
  `workflow_queue_verification_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 17 calls) and full live artifacts
  present, so `run-1773469269` is currently treated as transient browser
  startup variance rather than a standing blocker
- latest full-family reference:
  `run-1773469269` failed `1/2` on full `workflow_rich`; sibling case
  `workflow_queue_verification_billing_review` passed judged live with
  provider-backed inference and full live artifacts present, but
  `workflow_queue_verification_network_ops` failed before judged execution
  with `launch Chromium for agent mode: Driver internal error: Browser process
  exited ... before websocket URL could be resolved`
- latest exact workflow-rich closure:
  `run-1773469102` passed judged live on
  `workflow_queue_verification_network_ops` with provider-backed inference and
  full live artifacts present. The new first-snapshot pending follow-up lands
  strongly enough for the live model to complete queue verification after
  return, so the active rung now widens to full `workflow_rich`
- latest exact slice closure:
  `run-1773455124` passed judged live on
  `miniwob_click_checkboxes_transfer_core` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 1 call); with the prompt-visible
  negative-selection success cue present, the live model issued only
  `browser__click_element {"id":"btn_submit"}`
- latest full-family reference:
  `run-1773456913` passed `2/2` judged live on full `workflow` with
  provider-backed inference; both cases emitted non-zero provider calls and
  persisted `agent_state.json`, `inference_trace.json`, and
  `inference_calls.json`, so the ladder now advances to the workflow-rich
  sentinel `workflow_queue_verification_network_ops`
- latest exact-slice closure:
  `run-1773456815` passed judged live on
  `workflow_ticket_routing_network_ops` with provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 11 calls); live artifacts included
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`, and
  the model completed the full workflow path:
  login -> open `T-204` -> select `Network Ops` -> type note -> submit
- exact inner-loop dev target:
  full `workflow_reorder` family sweep
- smallest honest active gap:
  none currently active on the exact sentinel; full-family rerun pending
- current in-repo reduction:
  no new exact-slice reduction is pending; the latest shared verification fix
  is now retained on the authoritative live path. Once a queue refresh has
  already been observed, stale-queue pending guidance no longer keeps asking
  for another refresh, and the reordered queue now names the remaining visible
  distractor history link as the next grounded step instead of reopening the
  target ticket. Exact rerun `run-1773482569` validates that reduction; rerun
  full `workflow_reorder` next and classify only if the family reopens. Earlier
  shared runtime and verification fixes remain retained:
  DOM-fallback click verification is fixed and retained
  (focused-state capture plus DOM-identity verification), and
  startup browser-observation seeding is now wired so the first live browser
  cognition turn can act immediately when current semantics are already
  available locally; browser observations now expose native-select locator
  metadata and browser dropdown tools accept browser semantic IDs, and
  successful dropdown selection is now promoted into a verified recent-success
  signal; autocomplete suggestion/hint nodes now survive DOM fallback and
  AutoLens, and `browser__type` now surfaces grounded autocomplete post-state
  after a short settle window; active autocomplete is now framed as pending
  browser state and that moved the live model from premature submit to a
  `browser__key` attempt; `browser__key` now returns grounded post-key widget
  state, hidden assistive autocomplete nodes now survive the compact browser
  observation summary, and highlighted-candidate commit cues are now explicit
  enough to close `miniwob_use_autocomplete_smoke`; grounded scroll-state
  exposure for scrollable browser controls now reaches the prompt and moved the
  live model from blind wheel scrolling to `Home`, and key-target grounding now
  exposes when that key lands on the page; click-result grounding now exposes
  when a click already focused the intended scrollable control; immediate
  duplicate suppression for repeatable browser motion is now relaxed enough to
  let grounded repeated `PageUp` execute, and modifier-chord browser key JSON
  is now explicit enough in the generic tool surface and browser operating
  rules for the live model to emit the correct top-edge chord; generic browser
  key edge-settle completion is now also wired for near-complete top-edge /
  bottom-edge chords, and `run-1773452711` closed
  `miniwob_scroll_text_direction_smoke` after the grounded post-key state
  reached `scroll_top=0`; `run-1773452927` then closed full live `smoke`
  judged `8/8`; generic form-control selection state and label association now
  reach both browser observation and click verification, planner-facing
  post-selection follow-up guidance is now present, and redundant DOM-fallback
  aggregate containers are now pruned when descendant controls already ground
  the same content; `run-1773454272` closed the exact core sentinel with the
  live model selecting the requested radio and then clicking `Submit`;
  `run-1773454348` then widened cumulative `core` to `16/17` judged live and
  exposed a new planner miss on explicit no-selection instructions, so the
  next authoritative reduction became planner-side negative-selection
  discipline on the exact failing slice `miniwob_click_checkboxes_transfer_core`;
  the browser cognition prompt now also emits snapshot-derived pending and
  success cues for explicit no-selection end states, and `run-1773455124`
  closed that exact slice with a direct `Submit`; `run-1773455310` then closed
  full cumulative `core` judged `17/17`, so the ladder advanced to the
  workflow sentinel `workflow_ticket_routing_network_ops`; bridge-to-goal task
  detail propagation is now also wired, and `run-1773455998` proved the live
  model can log in and reach the target ticket detail page; delayed same-tab
  URL-change click verification is now also retained, and
  `browser__click_element` now falls back generically through selector /
  DOM-id activation when semantic link dispatch alone has no observable effect;
  `run-1773456815` closed the exact workflow sentinel with that shared runtime
  fix, and `run-1773456913` then closed full `workflow` judged live `2/2`, so
  the next authoritative reduction is the workflow-rich sentinel
  `workflow_queue_verification_network_ops`; auth-form pending guidance plus
  stale-success suppression now carry the live model through login, the browser
  snapshot artifact / prompt path now ranks omitted targets by actionability so
  locator-bearing late links survive serializer truncation, and
  `browser__snapshot` chat-history compaction now preserves the same ranked
  targets instead of raw-truncating them before cognition reuse; dropdown
  success cues now also point at the remaining visible form controls instead of
  only stating that the dropdown already succeeded, recent-success selection
  now respects cross-tool recency so an older dropdown cue cannot outrank a
  later click/navigation success, stricter link-click verification now forces
  selector fallback when a queue link only changes the DOM without actually
  navigating, and stale browser observations are now suppressed after
  URL-changing actions until a fresh snapshot lands; dropdown-success
  extraction now also accepts both raw and prefixed live tool payloads, and
  local prompt-history tests cover the `run-1773463415` ordering where an older
  click success sits beside a newer dropdown selection; `run-1773463785` now
  proves those reductions are landing because the live model completes the edit
  path and reaches queue re-entry. The next reduction is current-browser
  auth-form pending guidance without a history snapshot so the model stops
  wasting an early sign-in click and regains one step for final queue
  verification before the next exact rerun; `run-1773464145` validated that
  auth reduction and moved the frontier back onto dropdown continuation on the
  compacted snapshot path; `run-1773464350` then validated the compacted
  dropdown-success fix and moved the frontier onto stale-navigation prompt
  suppression when a fresh current-browser snapshot is already present;
  `run-1773464877` validated that observation reduction and moved the frontier
  back onto compact-target follow-up extraction; `run-1773465246` then proved
  that follow-up extraction is landing because the live model asked for the
  status dropdown directly, and `run-1773465746` tightened the remaining miss
  further to semantic-id continuity on mutable controls; stable label-shaped
  identity plus DOM-id alias continuity now lands on the authoritative live
  path, and `run-1773465980` proves the exact slice reaches queue re-entry with
  saved target state already correct. Generic prompt-side filter-mismatch
  verification guidance plus stale-success suppression now also land on the
  live path, `run-1773467018` confirms the stronger exact-control cue is
  visible, `run-1773468786` confirms the unchanged-snapshot guard now
  terminalizes the repeated inspect path instead of letting it stay harmless,
  and `run-1773469102` closes the sentinel once the first queue snapshot also
  emits snapshot-derived pending follow-up into immediate chat history.
  `run-1773469269` then widens full `workflow_rich` to `1/2` on transient
  browser startup variance, `run-1773469438` immediately re-closes that exact
  slice with full provider-backed artifacts, `run-1773469571` then closes full
  `workflow_rich` at `2/2` judged live, `run-1773469772` closes the
  workflow-audit sentinel, and `run-1773469870` then closes full
  `workflow_audit` at `2/2` judged live. Generic semantic-id typing fallback
  now also lands on the live path, omitted queue-row context now survives both
  serializer truncation and browser-snapshot history compaction, and the prompt
  now also emits generic cross-item history follow-up pending guidance while
  suppressing stale generic success framing after returning from one history
  page to a list view. `run-1773472243` then exposed an earlier planner miss:
  successful sign-in navigation still falls back to a generic finish-flavored
  click-success cue instead of naming next visible queue controls. That
  snapshot-aware success-signal reduction is now landed, covered by prompt
  history tests, and validated by `run-1773472876`; `run-1773473013` then
  widened full `workflow_mutation` and exposed the next exact live target as
  `workflow_mutation_isolation_network_ops` on a `verification_gap`, and
  `run-1773473228` tightens that same exact failure further: once `T-215`
  history is open, the saved dispatch-update row is already visible but the
  prompt still lacks a generic verification-to-next-step continuation, so the
  next move is to tighten history-page verification continuation before the
  exact rerun. Focused prompt-history reproduction now proves the intended
  shared pending cue is truncating under `PENDING_BROWSER_STATE_MAX_CHARS`
  before the actionable queue-return control survives, so the next shared fix
  is to front-load queue-return and next-item guidance while keeping the cue
  generic. `run-1773474004` validates that shared fix on the authoritative live
  path: the exact slice now passes with 17 provider calls and full live
  artifacts, so the active move widens back to the full family. The later
  sibling `workflow_mutation_isolation_billing_review` remains only a
  secondary planner diagnostic until the family rerun confirms the next
  frontier

Current target:

- current inner-loop target: reopened exact `core` slice
  `miniwob_click_option_core`
- run the authoritative live exact rerun with
  `COMPUTER_USE_SUITE_TASK_SET=core` and
  `COMPUTER_USE_SUITE_CASES=miniwob_click_option_core`
- if that exact slice closes, rerun full `core` immediately
- only after full `core` is green again, return to the full cumulative
  `stress` audit

Program end state:

- a state-of-the-art computer-use suite path that improved by sprinting on live
  failures from the bottom of the ladder upward
- fixes remain generic beyond the suite family that exposed them

## Rolling Window

This spec must self-update without drifting.

Keep:

- current frontier
- current blocker
- current rung
- next 2 rungs
- latest authoritative controls
- latest authoritative benchmark evidence
- active gap classifications

Compress or remove:

- superseded diagnostics
- closed-rung narration
- inactive-family detail
- repeated historical explanation

Retention rule:

- keep at most 3 authoritative references that still affect current decisions
- keep at most 2 diagnostic references per active blocker class
- summarize older history in one line if it still matters

## Validation status

Latest authoritative controls:

- local browser live control:
  `crates/cli/target/browser_live_runtime/run-1773436925`
  `HttpInferenceRuntime` + `gpt-4o-mini` passed cleanly
- local browser live control:
  `crates/cli/target/browser_live_runtime/run-1773437051`
  `HttpInferenceRuntime` + `gpt-4o` passed cleanly

Latest suite readiness evidence:

- 2026-03-13 diagnostic refactor: `computer_use_suite` now accepts
  `COMPUTER_USE_SUITE_AGENT_BACKEND=live_http`
- 2026-03-13 diagnostic refactor: live agent cases now persist
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`
  alongside existing bridge/kernel/screenshot artifacts
- 2026-03-13 diagnostic validation:
  `computer_use_suite_manifest_is_unique`,
  `computer_use_suite::tests::parse_agent_backend_accepts_live_http_aliases`,
  `computer_use_suite::harness::tests::agent_startup_issues_navigation_before_waiting_on_bridge_readiness`,
  and
  `computer_use_suite::harness::tests::hover_shape_recovery_waits_before_retrying_same_phase`
  all passed

Latest authoritative benchmark status:

- 2026-03-13 beginner sentinel pass:
  `target/computer_use_suite/run-1773442607`
  `miniwob_click_button_smoke` passed with live provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 2 calls)
- 2026-03-13 older beginner-family history compressed:
  authoritative live `smoke` improved from `4/8` to `5/8` before
  `miniwob_choose_list_smoke` became the active exact slice
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773445006`
  `miniwob_choose_list_smoke` passed with live provider-backed inference
  (`HttpInferenceRuntime`, `gpt-4o`, 2 calls); the live model selected
  `Australia`, observed the updated combobox state, and then clicked `Submit`
- 2026-03-13 beginner family rerun:
  `target/computer_use_suite/run-1773445832`
  full `smoke` passed `6/8` judged live; `miniwob_use_autocomplete_smoke` is
  now the first failing slice and `miniwob_scroll_text_direction_smoke` also
  remains red
- 2026-03-13 exact beginner reruns:
  `target/computer_use_suite/run-1773446469` and
  `target/computer_use_suite/run-1773446638`
  `miniwob_use_autocomplete_smoke` stayed red judged live even after the
  autocomplete observation patches; the live prompt after `browser__type`
  still lacked grounded autocomplete follow-up state, so the model typed
  `Poland` and clicked `Submit`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773447058`
  `miniwob_use_autocomplete_smoke` stayed red judged live after the
  autocomplete post-state wiring landed; the second provider call already saw
  `typed.autocomplete`, the explicit autocomplete follow-up cue, and the
  focused typed textbox, but still clicked `Submit`, so the active gap moved
  from `verification_gap` to `planner_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773447404`
  `miniwob_use_autocomplete_smoke` stayed red judged live after the
  planner-facing prompt fix, but the behavior improved: the second provider
  call switched from premature submit to `browser__key {"key":"Enter"}` before
  the slice fell back to submit; the active gap moved back to
  `verification_gap` because `browser__key` still does not surface grounded
  post-key widget state
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773447666`
  `miniwob_use_autocomplete_smoke` stayed red judged live after the
  key-verification fix, but the behavior improved again: the third provider
  call now saw that `Enter` left autocomplete active and still clicked
  `Submit`; the active gap moved back to `planner_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773447852`
  `miniwob_use_autocomplete_smoke` stayed red judged live after the stronger
  unresolved-key follow-up guidance; the second provider call reverted to
  immediate submit, which suggests the current planner-only fixes are noisy and
  the next shared reduction should improve prompt-visible grounding instead
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773448025`
  `miniwob_use_autocomplete_smoke` stayed red judged live after the assistive
  hint observation-summary fix, but the behavior improved again: the live
  model typed `Pol`, pressed `ArrowDown`, saw prompt-visible candidate text
  `Poland`, and still submitted instead of committing with `Enter`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773448168`
  `miniwob_use_autocomplete_smoke` passed judged live after the highlighted
  candidate commit cue landed
- 2026-03-13 beginner family rerun:
  `target/computer_use_suite/run-1773448273`
  full `smoke` passed `7/8` judged live; `miniwob_scroll_text_direction_smoke`
  is now the only remaining failing beginner-family slice
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773448540`
  `miniwob_scroll_text_direction_smoke` stayed red judged live; the model used
  only `browser__scroll`, but the tool returned only deltas and the compact
  browser observation still hid textarea scroll position, so the active gap
  tightened to `verification_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773449279`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after grounded
  scroll-state exposure landed; the live model now chose `browser__key`
  `Home`, proving the scrollable-textarea state and generic key guidance reached
  planning, but it never focused the textarea first and kept sending the key to
  the page/web area, so the active gap moved back to `planner_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773449582`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after key-target
  grounding landed; the live model reacted to the page-level `Home` miss by
  clicking the wrapper, and that first click focused the textarea, but
  `browser__click_element` still reported only the wrapper target, so later live
  turns kept replaying wrapper clicks instead of sending `Home` to the now
  focused textarea; the smallest honest gap tightened to `verification_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773450087`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after focused
  click-result grounding landed; the live model improved again and clicked the
  textarea semantic target directly before sending `Home` to the focused
  textarea, but the grounded post-key state still showed `scroll_top=257` with
  `can_scroll_up=true`, and the live planner kept repeating `Home`, so the
  active gap moved back to `planner_gap`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773450293`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  no-effect `Home` follow-up cue landed; the live model improved again and
  escalated from `Home` to `PageUp` and `Control+Home`, but it still clicked
  `Submit` while the focused textarea reported `scroll_top=2` with
  `can_scroll_up=true`, so the active gap remains `planner_gap` and now centers
  on explicit edge-completion discipline rather than key choice
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773450477`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  stronger edge-completion rule landed, but the live behavior regressed: the
  model focused the textarea and then fell back to repeated `Home` despite
  grounded post-key state still reporting `can_scroll_up=true`; the active gap
  remains `planner_gap`, now narrowed to making the no-repeat key escalation and
  edge-completion discipline land together instead of independently
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773450684`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  combined no-repeat-plus-edge-completion cue landed; the live model still
  repeated `Home` on the focused textarea while `can_scroll_up=true`, which
  suggests the remaining reduction is to turn that guidance into an explicit
  ban on the repeated key rather than a generic “ineffective edge key” warning
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773451014`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  explicit no-repeat cue landed, but the live behavior improved materially: the
  model focused the correct textarea, switched from `Home` to repeated
  `PageUp`, and kept the task unresolved while upward movement remained; the
  remaining blocker moved from `planner_gap` to `recovery_gap` because the
  executor skipped an immediate repeated `browser__key` replay as
  `success_duplicate_skip` and queued verification instead of allowing the
  continued motion
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773451360`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  duplicate-motion fix landed, but the repeated focused `PageUp` actions now
  executed cleanly down to `scroll_top=24`; the active gap moved back to
  `planner_gap` because the live model still spent the last step on another
  `PageUp` instead of escalating to a top-edge jump before timeout
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773451602`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  repeated-pagewise escalation cue landed; the prompt now told the live model
  to use `browser__key {"key":"Home","modifiers":["Control"]}`, but it still
  answered with plain `Home`, which tightened the active miss to
  modifier-chord discoverability on `browser__key`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773452375`
  `miniwob_scroll_text_direction_smoke` stayed red judged live after the
  modifier-chord discoverability fix landed, but the behavior improved again:
  the live model emitted
  `browser__key {"key":"Home","modifiers":["Control"]}` and the grounded key
  result reported `scroll_top=2` with `can_scroll_up=true`; the active gap
  tightened from `planner_gap` to `missing_keyboard_primitive`
- 2026-03-13 exact beginner rerun:
  `target/computer_use_suite/run-1773452711`
  `miniwob_scroll_text_direction_smoke` passed judged live after the generic
  browser key edge-settle reduction landed; the live model again emitted
  `browser__key {"key":"Home","modifiers":["Control"]}`, and the grounded
  post-key state now returned `scroll_top=0` with `can_scroll_up=false` before
  submit
- 2026-03-13 beginner family rerun:
  `target/computer_use_suite/run-1773452927`
  full `smoke` passed `8/8` judged live with provider-backed inference;
  all eight cases emitted non-zero provider calls and persisted
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`,
  so the ladder advances to the core sentinel `miniwob_click_option_core`
- 2026-03-13 core sentinel rerun:
  `target/computer_use_suite/run-1773453163`
  `miniwob_click_option_core` stayed red judged live with provider-backed
  inference (`HttpInferenceRuntime`, `gpt-4o`, 8 calls); the live model
  clicked the correct radio first, but the prompt-visible browser snapshot and
  click verification did not surface that the target option was now selected,
  so the run devolved into wrapper clicks and exited `NoEffectAfterAction`
- 2026-03-13 core sentinel rerun:
  `target/computer_use_suite/run-1773453559`
  `miniwob_click_option_core` stayed red judged live after the selection-state
  grounding landed, but the behavior improved materially: the live model now
  chose `radio_tecslmn`, and both the browser snapshot and click verification
  surfaced `checked=true`; the remaining miss tightened from
  `verification_gap` to `planner_gap` because the follow-up still clicked the
  enclosing form container instead of `btn_submit`
- 2026-03-13 core sentinel rerun:
  `target/computer_use_suite/run-1773454272`
  `miniwob_click_option_core` passed judged live with provider-backed
  inference (`HttpInferenceRuntime`, `gpt-4o`, 2 calls); after redundant
  DOM-fallback aggregate containers were pruned, the live model used the
  grounded control path directly: `radio_tecslmn` then `btn_submit`
- 2026-03-13 core audit rerun:
  `target/computer_use_suite/run-1773454348`
  full cumulative `core` passed `16/17` judged live with provider-backed
  inference; every case emitted non-zero provider calls and persisted
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`, and
  the only remaining red slice was `miniwob_click_checkboxes_transfer_core`
- 2026-03-13 exact core rerun:
  `target/computer_use_suite/run-1773455124`
  `miniwob_click_checkboxes_transfer_core` passed judged live with
  provider-backed inference (`HttpInferenceRuntime`, `gpt-4o`, 1 call); the
  prompt-visible no-selection success cue held, and the live model clicked
  only `btn_submit`
- 2026-03-13 core family rerun:
  `target/computer_use_suite/run-1773455310`
  full cumulative `core` passed `17/17` judged live with provider-backed
  inference; all 17 cases emitted non-zero provider calls and persisted
  `agent_state.json`, `inference_trace.json`, and `inference_calls.json`, so
  the ladder advances to the workflow sentinel
  `workflow_ticket_routing_network_ops`
- 2026-03-13 workflow sentinel rerun:
- 2026-03-13 workflow sentinel reruns:
  `target/computer_use_suite/run-1773455728`,
  `target/computer_use_suite/run-1773455998`, and
  `target/computer_use_suite/run-1773456297`
  `workflow_ticket_routing_network_ops` tightened honestly across the exact
  live loop until the remaining shared miss was semantic link activation
- 2026-03-13 workflow sentinel closure:
  `target/computer_use_suite/run-1773456815`
  `workflow_ticket_routing_network_ops` passed judged live with
  provider-backed inference (`HttpInferenceRuntime`, `gpt-4o`), but the gap
  is now closed on that sentinel: the live model logged in, opened `T-204`,
  selected `Network Ops`, typed the note, and submitted the update in 11 calls
- 2026-03-13 workflow family rerun:
  `target/computer_use_suite/run-1773456913`
  full `workflow` passed `2/2` judged live with provider-backed inference;
  both cases recorded 11 provider calls and persisted `agent_state.json`,
  `inference_trace.json`, and `inference_calls.json`, so the ladder advances
  to the workflow-rich sentinel `workflow_queue_verification_network_ops`

Current live command shapes:

- current family rerun:
  `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=workflow cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`
- exact slice rerun:
  `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=workflow COMPUTER_USE_SUITE_CASES=<case> cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`

Validation rules:

- only provider-backed `computer_use_suite` agent runs count as benchmark
  progress
- deterministic `oracle`, `runtime`, and deterministic `agent` runs are
  regression-only
- logs, screenshots, or browser motion do not count as benchmark success
- live suite passes must remain auditable from suite artifacts

## Known failures / unrelated issues

- latest closed infra reduction:
  `/tmp/miniwob-plusplus` now satisfies MiniWoB assets for live suite runs
- latest closed shared fixes:
  bridge startup stderr artifacting, honest infra classification, live-agent
  startup navigation/readiness gating, and `notRendered` AX fallback to DOM
- `live_http` requires a valid `OPENAI_API_KEY`; without it, live suite runs are
  blocked before benchmark execution
- repo-wide warnings and unrelated dirty-worktree changes are not benchmark
  signal

## Date-stamped implementation notes

- 2026-03-13: extracted deterministic suite agent policy from
  `crates/cli/tests/computer_use_suite/harness.rs` into
  `crates/cli/tests/computer_use_suite/harness/agent_backend.rs`
- 2026-03-13: extracted agent-case execution and backend selection into
  `crates/cli/tests/computer_use_suite/harness/agent_runner.rs`
- 2026-03-13: extracted mode/report orchestration into
  `crates/cli/tests/computer_use_suite/harness/mode_runner.rs`
- 2026-03-13: added explicit suite agent backend selection via
  `COMPUTER_USE_SUITE_AGENT_BACKEND` with current values:
  `deterministic_miniwob`, `live_http`
- 2026-03-13: aligned the ladder to sentinel-first progression:
  one sentinel case, then the full family, then the next family sentinel

## Benchmark Snapshot

| Family / rung | Status | Authoritative result | Command shape | Artifact root | Smallest honest exit criterion |
| --- | --- | --- | --- | --- | --- |
| live sentinel: `miniwob_click_button_smoke` | passed | `run-1773442607`: pass, `HttpInferenceRuntime`, `gpt-4o`, 2 provider calls, judged success | `... AGENT_BACKEND=live_http TASK_SET=smoke CASES=miniwob_click_button_smoke ...` | `run-1773442607/agent/miniwob_click_button_smoke` | closed |
| full `smoke` | passed | `run-1773452927`: `8/8` judged live, `HttpInferenceRuntime`, `gpt-4o`; all eight cases recorded non-zero provider calls plus `agent_state.json`, `inference_trace.json`, and `inference_calls.json` | `... AGENT_BACKEND=live_http TASK_SET=smoke ...` | `run-1773452927/agent` | closed |
| core sentinel: `miniwob_click_option_core` | passed | `run-1773454272`: pass, `HttpInferenceRuntime`, `gpt-4o`, 2 provider calls; the live model chose `radio_tecslmn` and then `btn_submit` | `... AGENT_BACKEND=live_http TASK_SET=core CASES=miniwob_click_option_core ...` | `run-1773454272/agent/miniwob_click_option_core` | closed |
| full `core` audit | passed | `run-1773455310`: `17/17` judged live; all 17 cases recorded non-zero provider calls and persisted `agent_state.json`, `inference_trace.json`, and `inference_calls.json` | `... AGENT_BACKEND=live_http TASK_SET=core ...` | `run-1773455310/agent` | closed |
| workflow sentinel: `workflow_ticket_routing_network_ops` | passed | `run-1773456815`: judged pass, `HttpInferenceRuntime`, `gpt-4o`, 11 provider calls; live artifacts present and the model completed login, ticket-open, assignee selection, note entry, and submit | `... AGENT_BACKEND=live_http TASK_SET=workflow CASES=workflow_ticket_routing_network_ops ...` | `run-1773456815/agent/workflow_ticket_routing_network_ops` | closed |
| full `workflow` | passed | `run-1773456913`: `2/2` judged live; both cases recorded non-zero provider calls and persisted `agent_state.json`, `inference_trace.json`, and `inference_calls.json` | `... AGENT_BACKEND=live_http TASK_SET=workflow ...` | `run-1773456913/agent` | closed |
| workflow-rich sentinel: `workflow_queue_verification_network_ops` | passed | `run-1773469102`: judged pass with provider-backed inference and full live artifacts present; the first queue snapshot follow-up lands strongly enough for the live model to complete post-confirm queue verification | `... AGENT_BACKEND=live_http TASK_SET=workflow_rich CASES=workflow_queue_verification_network_ops ...` | `run-1773469102/agent/workflow_queue_verification_network_ops` | closed |
| full `workflow_rich` | passed | `run-1773469571`: `2/2` judged live; both cases recorded non-zero provider calls (`17`, `15`) and persisted `agent_state.json`, `inference_trace.json`, and `inference_calls.json`. `run-1773469269` is retained only as transient browser-startup variance because `run-1773469438` immediately re-closed the exact slice | `... AGENT_BACKEND=live_http TASK_SET=workflow_rich ...` | `run-1773469571/agent` | closed |
| workflow-audit sentinel: `workflow_audit_history_network_ops` | passed | `run-1773469772`: judged pass with provider-backed inference (`15` calls) and full live artifacts present | `... AGENT_BACKEND=live_http TASK_SET=workflow_audit CASES=workflow_audit_history_network_ops ...` | `run-1773469772/agent/workflow_audit_history_network_ops` | closed |
| full `workflow_audit` | passed | `run-1773469870`: `2/2` judged live; both cases recorded non-zero provider calls (`15`, `13`) and persisted `agent_state.json`, `inference_trace.json`, and `inference_calls.json` | `... AGENT_BACKEND=live_http TASK_SET=workflow_audit ...` | `run-1773469870/agent` | closed |
| workflow-mutation sentinel: `workflow_mutation_isolation_network_ops` | passed | `run-1773475037`: judged pass with provider-backed inference (`30` calls) and full live artifacts present; the stricter viewed-history detector now preserves the cross-item queue-return follow-up strongly enough for the exact slice to finish live by switching from `T-215` back to `T-204` history | `... AGENT_BACKEND=live_http TASK_SET=workflow_mutation CASES=workflow_mutation_isolation_network_ops ...` | `run-1773475037/agent/workflow_mutation_isolation_network_ops` | closed |
| full `workflow_mutation` | passed | `run-1773479507`: judged live `2/2` with provider-backed inference and full live artifacts present. Exact rerun `run-1773479455` first re-closed `workflow_mutation_isolation_billing_review` by landing the concrete-ticket queue-return handoff after verified `T-318` history, and the immediate family rerun confirmed both mutation cases now pass together on the authoritative live harness | `... AGENT_BACKEND=live_http TASK_SET=workflow_mutation ...` | `run-1773479507/agent` | closed |
| workflow-reorder sentinel: `workflow_stale_queue_reorder_network_ops` | passed | `run-1773481680`: judged pass with provider-backed inference (`HttpInferenceRuntime`, `gpt-4o`, 17 calls) and full live artifacts present. The action trace now closes the intended workflow: login, update `T-215`, confirm, queue return, `inp_queue_sort=Recently Updated`, `btn_apply_filters`, then `T-204` history | `... AGENT_BACKEND=live_http TASK_SET=workflow_reorder CASES=workflow_stale_queue_reorder_network_ops ...` | `run-1773481680/agent/workflow_stale_queue_reorder_network_ops` | closed |
| workflow-reorder exact follow-up: `workflow_stale_queue_reorder_billing_review` | passed | `run-1773483141`: judged pass with provider-backed inference (`HttpInferenceRuntime`, `gpt-4o`, 20 calls) and full live artifacts present. After refresh the live model again goes directly from `btn_apply_filters` to distractor history `lnk_history_807ebf`; this exact closure specifically holds even when the current prompt frame has to fall back to the richer earlier queue snapshot to recover the handoff | `... AGENT_BACKEND=live_http TASK_SET=workflow_reorder CASES=workflow_stale_queue_reorder_billing_review ...` | `run-1773483141/agent/workflow_stale_queue_reorder_billing_review` | closed |
| full `workflow_reorder` | passed | `run-1773483313`: judged live `2/2` with provider-backed inference and full live artifacts present. `workflow_stale_queue_reorder_network_ops` recorded `16` provider calls, `workflow_stale_queue_reorder_billing_review` recorded `17`, and the immediate family rerun confirmed the reordered-queue handoff now holds across both cases on the authoritative live harness | `... AGENT_BACKEND=live_http TASK_SET=workflow_reorder ...` | `run-1773483313/agent` | closed |
| stress sentinel: `miniwob_click_collapsible_2_stress` | passed | `run-1773484611`: judged live pass with provider-backed inference (`live_http`, `gpt-4o`, 5 calls) and full live artifacts present. After the new exact-target pending cue landed, the live model finished the tabbed-collapsible task by clicking the grounded visible target instead of the surrounding panel | `... AGENT_BACKEND=live_http TASK_SET=stress CASES=miniwob_click_collapsible_2_stress ...` | `run-1773484611/agent/miniwob_click_collapsible_2_stress` | closed |
| full `stress` audit | in progress | `run-1773484641`: judged live `15/19` with provider-backed inference and full live artifacts present. The cumulative audit reopened four cases: `miniwob_click_option_core` and `miniwob_click_checkboxes_core` as `verification_gap` / `TargetNotFound`, plus `miniwob_click_checkboxes_transfer_core` and `miniwob_search_engine_stress` as `planner_gap`. Exact reruns `run-1773485940`, `run-1773486459`, `run-1773486774`, `run-1773487291`, `run-1773489181`, and `run-1773489982` re-closed the exact frontier, and full cumulative `core` rerun `run-1773490053` now passes `17/17` with provider-backed inference and full live artifacts present. Superseding cumulative `stress` rerun `run-1773490463` is now in flight and has already re-cleared every previously reopened `core`-derived case through `miniwob_click_button_sequence_core` without any `error.txt` or zero-call failures | `... AGENT_BACKEND=live_http TASK_SET=stress ...` | `run-1773490463/agent` | if red, collapse to the first exact failing stress slice; if green, close the stress rung |

## Capability Gap Matrix

Only gaps exposed by live suite runs are active.

| Gap class | Current status | Handling |
| --- | --- | --- |
| `missing_pointer_primitive` | dormant | `run-1773456815` closed the visible-link activation miss enough for the workflow sentinel to pass; reopen only on fresh live evidence |
| `missing_selection_primitive` | dormant | reopen only on live evidence |
| `missing_keyboard_primitive` | dormant | `run-1773452711` closed the browser edge-settle miss on top-edge / bottom-edge jump chords; reopen only on fresh live evidence |
| `missing_clipboard_primitive` | dormant | reopen only on live evidence |
| `observation_gap` | dormant | exact stress rerun `run-1773484611` closed the visible-target handoff on the authoritative live path, so keep this dormant unless a later live rerun again clicks surrounding containers instead of a grounded visible target element |
| `verification_gap` | diagnostic | cumulative `stress` audit `run-1773484641` reopened this class on `miniwob_click_option_core` and `miniwob_click_checkboxes_core`, both with `TargetNotFound` and provider-backed inference. Exact reruns have now tightened `miniwob_click_option_core` past verification into later bridge and planner stages, but keep verification diagnostic active because `miniwob_click_checkboxes_core` is still unreduced and full `core` is not yet re-closed |
| `planner_gap` | diagnostic | exact rerun `run-1773486459` exposed this on the first reopened exact slice, and exact rerun `run-1773486774` then closed that planner miss live. Full cumulative `core` rerun `run-1773487386` reopens the class on a different exact slice: `miniwob_use_autocomplete_smoke` typed the right string but still submitted and completed while RECENT PENDING BROWSER STATE said the autocomplete widget was unresolved. Keep the class diagnostic because cumulative `stress` still also has unreduced planner-red cases (`miniwob_search_engine_stress`) |
| `recovery_gap` | dormant | `run-1773478729` tightened the smaller shared cause to queue-return item extraction and alternate-link filtering after verified `T-318` history. Exact rerun `run-1773479455` and full-family rerun `run-1773479507` close that gap on the authoritative live path, so keep it dormant unless workflow-reorder or stress reopens a fresh recovery miss |
| `infra_or_bridge_gap` | dormant | exact rerun `run-1773485940` exposed a live lifecycle-tool mismatch on `miniwob_click_option_core`, and exact rerun `run-1773486459` proved that piece is fixed: `agent__complete` is visible and callable during the turnover prompt. Exact rerun `run-1773486774` then exposed a smaller bridge-accounting miss, and exact rerun `run-1773487291` closed that turnover-accounting path on the authoritative live harness. Full cumulative `core` rerun `run-1773489311` later reopened the class on Chromium launch before websocket resolution, but exact rerun `run-1773489982` plus widened family rerun `run-1773490053` close that launch-instability branch as well. Reopen only on fresh live evidence |

## Benchmark Escalation Ladder

1. Beginner sentinel
   Status: passed.
   Objective:
   - `miniwob_click_button_smoke` live with `live_http`
   Exact command shape:
   - `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=smoke COMPUTER_USE_SUITE_CASES=miniwob_click_button_smoke cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`
   Exit criterion:
   - closed by `run-1773442607`

2. Beginner family sweep
   Status: passed.
   Objective:
   - rerun full `smoke`
   - if red, drop immediately to the exact first failing `smoke` slice
   Active reduction:
   - exact autocomplete slice is closed
   - `run-1773448540` closed the scroll-state verification gap enough to move
     behavior
   - `run-1773449279` closed enough to prove the model can choose `Home`
   - `run-1773449582` closed enough to ground click-driven focus
   - `run-1773450087` closed enough to make the model change keys
   - `run-1773450293` closed enough to expose early-submit edge discipline
   - `run-1773450477` and `run-1773450684` exposed the remaining planner miss on
     repeated `Home`
   - `run-1773451014` exposed the duplicate-motion execution blocker
   - `run-1773451360` closed enough of that execution blocker to expose the
     next planner miss: repeated `PageUp` now executes, but the model still
     needs a stronger edge-jump escalation cue to finish top-edge tasks before
     timeout
   - `run-1773451602` proved the stronger edge-jump cue reached the prompt, but
     the model still answered with plain `Home`; that exposed the remaining
     modifier-chord discoverability miss on `browser__key`
   - `run-1773452375` closed that discoverability miss enough for the live
     model to emit `browser__key {"key":"Home","modifiers":["Control"]}`, but
     the browser key primitive still stopped at `scroll_top=2`, so the active
     reduction is now keyboard edge-settle completion rather than planner cueing
   - `run-1773452711` closed that remaining keyboard primitive gap; the exact
     scroll sentinel is now green and the active rung widens to the full
     `smoke` family
   - `run-1773452927` closed the widened family rerun at `8/8` judged live, so
     the beginner ladder is now complete
   Immediate validation:
   - closed by `run-1773452927`
   Exit criterion:
   - closed by `run-1773452927`

3. Core sentinel
   Status: passed.
   Objective:
   - run `miniwob_click_option_core` live before widening to cumulative `core`
   Active reduction:
   - `run-1773453163` proved the live model can choose the correct radio, but
     the browser observation / click verification path did not ground that the
     requested option was now selected
   - `run-1773453559` closed that state-grounding miss enough for the live
     model to pick `radio_tecslmn` and see `checked=true`, so the remaining gap
     is now planner-facing follow-up discipline rather than more state plumbing
   - `run-1773453798` proved that the new planner-facing cue did not materially
     change behavior: the live model still repeatedly targeted the aggregate
     container `grp_tecslmn_ex8_krcwls_ao07c6_e2a_` even while `radio_tecslmn`
     was visibly `checked=true` and `btn_submit` remained present, so the
     active gap tightens to aggregate-container salience in browser observation
   - `run-1773454272` closed the exact sentinel after redundant DOM-fallback
     aggregate containers were pruned; the live model now used the grounded
     control path directly: `radio_tecslmn` -> `btn_submit`
   Immediate validation:
   - closed by `run-1773454272`

4. Core audit
   Status: passed.
   Objective:
   - run full cumulative `core`
   Immediate validation:
   - `run-1773454348` widened cumulative `core` to `16/17` judged live
   - `run-1773455124` closed the only red slice
     `miniwob_click_checkboxes_transfer_core` after the negative-selection
     planner cue landed
   - `run-1773455310` then closed full cumulative `core` at `17/17` judged
     live
   Exit criterion:
   - closed by `run-1773455310`

5. Workflow sentinel and family sweep
   Status: passed.
   Objective:
   - run the workflow sentinel `workflow_ticket_routing_network_ops` live
   - if green, rerun full `workflow`
   Active reduction:
   - `run-1773455728` exposed a bridge-to-prompt task-detail loss on the exact
     workflow sentinel: the bridge already knew the full task brief and
     credentials, but the live prompt started from the generic workflow slug
     and the model spent all 12 provider calls on repeated `browser__snapshot`
   - `run-1773455998` closed that bridge loss enough for the live model to log
     in, open `T-204`, and expose a same-tab click verification miss on the
     ticket-link navigation path
   - `run-1773456297` stayed red after delayed URL-change verification landed:
     semantic `browser__click_element` still no-op'd on visible link
     `lnk_t_204`, recovery spent the remaining steps on retries and waits, and
     the slice hit `system::max_steps_reached` before the selector-click remedy
     could execute, so the next shared reduction is generic selector / DOM-id
     fallback activation inside `browser__click_element`
   - `run-1773456815` closed the exact workflow sentinel once that generic
     selector / DOM-id fallback landed, so the active rung now widens to the
     full `workflow` family
   - `run-1773456913` then closed full `workflow` at `2/2` judged live
   Exit criterion:
   - closed by `run-1773456913`

6. Workflow-rich sentinel and family sweep
   Status: passed.
   Objective:
   - run the workflow-rich sentinel `workflow_queue_verification_network_ops`
     live
   - if green, rerun full `workflow_rich`
   - if red, stay on that exact workflow-rich slice first
   Active reduction:
   - `run-1773457090` failed before live inference with
     `capture_raw_screen not implemented in computer_use_suite`; browser-backed
     raw-screen capture in the suite GUI harness cleared that startup blocker
   - `run-1773457300` then exposed the first real workflow-rich behavior gap:
     the queue snapshot still kept aggregate cell `grp_t_215` more salient than
     actionable link `#ticket-link-t-215`, so the live model looped on
     noninteractive cell clicks and never opened the ticket; the next shared
     reduction is redundant DOM-fallback table-cell aggregate pruning before
     rerunning the exact sentinel
   - `run-1773457540` proved table-cell aggregate pruning alone was not enough:
     the surviving `grp_t_215` target now mapped to an inert `code` wrapper,
     which tightened the remaining reduction from wrapper pruning to broader
     snapshot child-budget salience
   - `run-1773457727` stayed red even after serializer-side late-child
     preservation landed; authoritative artifacts showed the bridge already had
     actionable link `#ticket-link-t-215`, but the prompt-visible snapshot
     still truncated the queue at aggregate `grp_t_202_f...`, so the next
     shared reduction is observation compaction that promotes actionable
     descendants beneath high-salience aggregates into the prompt-visible
     browser XML before rerunning the exact sentinel
   - `run-1773458127` proved that observation compaction was still not reaching
     the authoritative browser snapshot artifact: the exact slice again stayed
     on queue-page no-effect loops while `snapshot_*.xml` still ended at the
     truncated aggregate table view, so the next shared reduction expanded from
     serializer child selection alone to the full browser observation surface
     (snapshot artifact plus prompt compaction)
   - `run-1773458527` showed that the full observation-surface reduction is now
     reaching the live prompt: browser context includes `IMPORTANT TARGETS`
     summaries, but the live model still clicked `Sign in` before completing
     login and then exhausted the step budget on repeated snapshots; the next
     reduction is now planner-side sequencing / progress discipline on the same
     exact sentinel, after one more confirming exact rerun
   - `run-1773458899` proved the auth-form planner cue is helping: the live
     model now completes login, reaches the queue, and acts on the correct
     search/filter controls, but the queue view already loads with the required
     search and status filter values, and the extra targeted
     `browser__type {"selector":"#queue-search","text":"fiber"}` appended into
     `fiberfiber`, collapsing the queue to zero results; the next shared
     reduction is generic typed-input verification / idempotence before
     rerunning the exact sentinel
   - `run-1773459517` validated that typed-input idempotence enough to remove
     `fiberfiber` as the first blocker, but the live model then stalled on the
     visible login form after both credentials were present: the prompt still
     carried the stale no-repeat click success cue and no stronger pending
     instruction to retry the sign-in action, so the next shared reduction is
     auth-form progress guidance plus suppression of stale success framing while
     auth completion remains pending
   - `run-1773459756` proved that auth-form progress guidance is now landing:
     the live model logs in, returns to the queue, reuses the already-correct
     queue search, and applies the filter; the remaining blocker tightened from
     planner sequencing to observation truncation because `snapshot_9.xml`
     still preserves only `ticket-link-t-202` plus omitted structural row/cell
     fragments, so the exact live model never receives `T-215` as a grounded
     click target and falls into repeated snapshots
   - `run-1773460388` proved that serializer-side omitted-target preservation
     is now landing in the authoritative snapshot artifact itself:
     `snapshot_8.xml` and `snapshot_11.xml` both include
     `ticket-link-t-202`, `ticket-link-t-204`, and `ticket-link-t-215`; the
     remaining blocker tightened again inside browser observation reuse because
     the stored `browser__snapshot` chat history still raw-truncates before the
     live cognition turn rebuilds `RECENT BROWSER OBSERVATION`, leaving only
     the queue controls and pushing the model back onto aggregate `grp_t_215`
   - `run-1773460816` proved that browser-snapshot chat-history compaction is
     now landing in the live prompt: `RECENT BROWSER OBSERVATION` exposes
     `lnk_t_215`, the live model opens the ticket detail page, and it sets the
     assignee to `Network Ops`; the remaining blocker tightened from
     observation reuse to planner follow-through because the model still
     repeats the completed assignee dropdown instead of moving to the visible
     status, note, and review controls
   - `run-1773461147` then showed that the stronger dropdown cue is still not
     enough on its own: after the queue filter succeeds and `T-215` is opened,
     the prompt can keep surfacing the older queue-filter dropdown success
     instead of the newer click/navigation success, so the exact slice remains
     blocked on stale recent-success ordering rather than missing browser state
   - `run-1773461714` reran the exact slice after that shared prompt fix
     landed, but the live trajectory regressed earlier and ignored the
     prompt-visible auth pending cue; treat that as noisy planner variance
   - `run-1773461876` then validated the targeted prompt fix on a deeper
     trajectory: after `lnk_t_215`, `RECENT SUCCESS SIGNAL` now surfaces the
     newer click success rather than the stale dropdown cue, but the exact
     slice still stalls because `browser__click_element` accepts a queue-link
     geometry click as success on tree change alone while the URL stays on the
     queue and selector fallback never runs
   - `run-1773462193` validates the stricter link-click verification fix:
     `lnk_t_215` opens through selector fallback, the live model reaches ticket
     detail, sets assignee/status/note, and clicks `Review update`; the next
     blocker is now stale post-navigation observation reuse, because the prompt
     still shows the ticket snapshot after the URL changes to `/review`, so the
     model goes straight to `lnk_queue` without first observing or confirming
     the review page
   - `run-1773462851` validates that the post-navigation snapshot fix now
     lands: the live model reaches `btn_confirm_update`, snapshots the
     confirmation page, and returns to the queue. The next blocker is that the
     live prompt still keeps the stale generic click-success cue after recent
     assignee/status dropdown selections instead of surfacing a dropdown
     follow-up cue, so the model skips the required note and confirms an empty
     saved note before queue verification
   - `run-1773463302` reran the exact slice after the dropdown-parser reduction
     landed locally, but the trajectory regressed early and stayed on login
     even though the prompt explicitly said both credentials were filled and the
     next action should be the sign-in click; treat that as noisy planner
     variance, not as a verdict on the current reduction
   - `run-1773463415` reran the exact slice on a deeper trajectory: it got
     through login, opened `T-215`, and successfully selected
     `Network Ops` on `inp_assign_team`, but the next prompt still showed the
     generic click-success cue even though `RECENT SESSION EVENTS` already
     contained the successful raw dropdown output; the model then repeated the
     same assignee selection until recovery hit stale semantic ids
   - `run-1773463785` validated that the dropdown / navigation reductions are
     now landing end-to-end: the live model completed login, queue search,
     ticket open, assignee/status/note edit, review, confirmation, and queue
     return, but it still spent an avoidable early `btn_sign_in` click after
     typing only the username and exhausted the step budget immediately after
     re-entering the queue while the filter still hid the escalated ticket
   - `run-1773464145` validated that the auth-fallback reduction landed: the
     prompt after typing only the username now explicitly says not to click
     `Sign in` yet, the live model fills the password first, and the early
     wasted login click disappears. The remaining blocker is back on the detail
     form: after selecting assignee, the prompt still keeps the generic
     click-success cue because the compacted snapshot path preserves
     `IMPORTANT TARGETS` summaries like `combobox#inp_assign_team` rather than
     the raw `id="inp_assign_team"` marker the dropdown-success reducer
     currently expects
   - `run-1773464350` validated that the compacted dropdown-success reduction
     landed: the live model completed login, ticket edit, review, confirm, and
     queue return, and bridge state showed the saved target already matches the
     requested assignee / status / note. The remaining miss is now step-budget
     loss on redundant post-navigation snapshots, because the prompt still says
     to take `browser__snapshot` after URL-changing clicks even when a fresh
     current-browser observation is already available for the new page
   - `run-1773464877` validated that the stale-navigation suppression landed:
     the post-ticket and post-queue prompts no longer force a fresh
     `browser__snapshot` on the live path. The remaining miss tightened back to
     compact follow-up extraction, because the assignee-success cue still
     points at `lnk_queue` / `heading_ticket_t_215` instead of the remaining
     status / note / review controls and the live model confirms the wrong
     saved status
   - `run-1773465246` proved that the compact follow-up extraction landed:
     the live model attempted the status dropdown directly, which showed the
     next remaining miss was semantic-id continuity rather than missing prompt
     follow-up
   - `run-1773465746` then tightened that continuity miss: after a successful
     assignee selection, the current live snapshot renamed the same control
     from `inp_assign_team` to `inp_network_ops`, so the model replayed the
     stale earlier id and recovery exhausted on repeated `TargetNotFound`
   - `run-1773465980` validates that stable label-first semantic ids plus
     DOM-id alias continuity now land on the live path: the model completes
     login, queue search, ticket open, assignee/status/note edit, review,
     confirmation, and queue return, but the remaining blocker moves to
     post-confirm verification because the queue still shows
     `Queue status filter = Awaiting Dispatch` and the prompt leaves the model
     snapshotting instead of adjusting that filter before checking the updated
     row
   - `run-1773466761` validates that the generic filter-mismatch pending cue
     and stale-success suppression now reach the live prompt, but the model
     still ignores that grounded contradiction and spends ordinals `14-18` on
     repeated `browser__snapshot`
   - `run-1773467018` validates that even the stronger exact-control cue lands:
     the prompt names `inp_queue_status_filter` and recommends
     `browser__select_dropdown`, yet the live model still burns the remaining
     steps on snapshots
   - `run-1773467152` validates that the broader no-snapshot planner rule lands
     partially: the live model now clicks back to the queue directly after
     confirm, but once the queue is visible it still spends ordinals `15-18`
     on repeated unchanged snapshots instead of changing the visible filter
   - `run-1773468786` validates that the unchanged-snapshot recovery now lands:
     ordinal `18` turns into `ERROR_CLASS=NoEffectAfterAction` instead of yet
     another silent queue snapshot, but the first queue snapshot still does not
     tell the model concretely enough to act on the visible filter
   - `run-1773469102` closes the exact sentinel once the first queue snapshot
     also emits snapshot-derived pending browser-state follow-up directly into
     immediate chat history
   - `run-1773469269` widens full `workflow_rich` to `1/2`: sibling case
     `workflow_queue_verification_billing_review` passes judged live with full
     provider-backed artifacts, but
     `workflow_queue_verification_network_ops` fails before judged execution
     because Chromium exits before the browser driver resolves a websocket URL
   - `run-1773469438` immediately re-closes
     `workflow_queue_verification_network_ops` with 17 provider calls and full
     live artifacts, so the browser launch failure is currently treated as
     transient variance rather than a standing suite defect
   - `run-1773469571` then closes full `workflow_rich` at `2/2` judged live
     with non-zero provider calls on both cases, so rung 6 is complete
   Exit criterion:
   - closed by `run-1773469571`

7. Workflow-audit sentinel and family sweep
   Status: passed.
   Objective:
   - run `workflow_audit_history_network_ops` live, then full `workflow_audit`
   Active reduction:
   - `run-1773469772` closes the exact sentinel
     `workflow_audit_history_network_ops` with 15 provider calls and full live
     artifacts, so the active move is to rerun full `workflow_audit`
   - `run-1773469870` then closes full `workflow_audit` at `2/2` judged live
     with non-zero provider calls on both cases, so rung 7 is complete
   Exit criterion:
   - closed by `run-1773469870`

8. Workflow-mutation sentinel and family sweep
   Status: in progress.
   Objective:
   - run `workflow_mutation_isolation_network_ops` live, then full
     `workflow_mutation`
   Active reduction:
   - `run-1773470012` exposed the first exact red slice after workflow-audit:
     reopened `T-215` reused semantic note id `inp_dispatch_note` as a CSS
     selector and recovery burned the remaining steps
   - `run-1773470424` proves the generic typing fallback now lands because the
     exact slice gets past note entry, `btn_review_update`, and
     `btn_confirm_update`
   - `run-1773471131` and `run-1773471409` prove the omitted queue-row context
     now reaches prompt-visible observation and compacted history, but after
     returning from `T-215` history the prompt still lacks explicit cross-item
     history continuation and the live model reopens `T-215`
   - `run-1773472243` regressed earlier than that later frontier: the live
     model reaches the filtered queue right after sign-in, but the prompt still
     frames the successful navigation too generically and the run burns ordinals
     `4-23` on snapshots and inert aggregate clicks instead of acting on a
     visible queue control or ticket link
   - current exact reduction: the shared snapshot-aware post-navigation
     continuation cue is now landed, including suppression of the stale
     navigation-observation gate when a current snapshot is already available,
     while retaining the later cross-item history follow-up cue; next rerun
     `workflow_mutation_isolation_network_ops`
   - `run-1773472876` closes the exact mutation sentinel with 30 provider calls
     and full live artifacts, so the rung widens to full `workflow_mutation`
   - `run-1773473013` then fails full `workflow_mutation` at `0/2`; the first
     failing case in family order is
     `workflow_mutation_isolation_network_ops` on `verification_gap`, so the
     active move collapses back to that exact slice before touching the later
     sibling `planner_gap` on `workflow_mutation_isolation_billing_review`
   - `run-1773473228` confirms the first exact failure is stable and narrows it
     further: after opening `T-215` history the saved dispatch-update row is
     already visible, but the prompt still lacks a generic verification
     continuation that sends the live model back toward the next required
     history check, so the current exact reduction is history-page
     verification continuation on the authoritative exact slice
   - focused prompt-history reproduction now proves the intended shared cue is
     truncating under `PENDING_BROWSER_STATE_MAX_CHARS` before `` `lnk_queue` ``
     survives, so the next exact reduction is to front-load queue-return and
     next-item guidance inside the generic history-page verification cue
   - `run-1773474004` validates that shared reduction on the authoritative live
     path: the exact slice passes with 17 provider calls and full live
     artifacts, so the active move widens back to full `workflow_mutation`
   - `run-1773474203` then fails full `workflow_mutation` at `0/2`; the first
     failing case in family order remains
     `workflow_mutation_isolation_network_ops`, but its suite classification
     has now moved to `planner_gap` (`28` provider calls), while sibling case
     `workflow_mutation_isolation_billing_review` is the retained
     `verification_gap` diagnostic (`33` provider calls). The active move
     collapses back to the exact `workflow_mutation_isolation_network_ops`
     slice before touching the sibling case again
   - `run-1773474416` confirms that first exact failure is stable and narrows
     it further: after returning from `T-215` history to the queue, the prompt
     still emits only a generic click-success cue instead of the intended
     cross-item history follow-up. Exact prompt inspection shows queue
     snapshots with visible history links are still being counted as viewed
     history pages, which suppresses the pending cue that should name `T-204`
     / `lnk_history_4c23bd` as the next grounded verification step
   - the shared history-follow-up detector now only counts actual history-page
     snapshots when tracking viewed items, and focused prompt-history tests
     cover the exact polluted-queue sequence from `run-1773474416`; next move
     is the exact authoritative live rerun on
     `workflow_mutation_isolation_network_ops`
   - `run-1773474910` then regresses earlier with `kernel_successes=0`: the
     live model burns steps on aggregate `grp_login_divide_queue` clicks and
     a cognition timeout forces recovery before the run ever reaches the
     post-history queue-return frontier. Because that rerun did not exercise
     the new history-follow-up fix, the next move is one more exact rerun to
     classify the newest failure as transient variance or the next standing
     blocker
   - `run-1773475037` immediately re-closes the exact slice with 30 provider
     calls and full live artifacts: after saving `T-215`, the live model now
     returns to the queue, opens `T-215` history, returns again, and then
     opens `T-204` history. This treats `run-1773474910` as transient variance
     and widens the rung back to full `workflow_mutation`
   - `run-1773475196` then improves full `workflow_mutation` to `1/2`: the
     re-closed `network_ops` slice stays green in-family, and the frontier
     genuinely moves to the sibling exact slice
     `workflow_mutation_isolation_billing_review`, now classified as
     `recovery_gap` (`TimeoutOrHang`, `4` provider calls)
   - `run-1773475353` tightens that sibling exact slice to the smaller shared
     cause: on `T-318` audit history the prompt still sees only the pre-save
     `Requested billing callback` row, but no pending mismatch cue appears, so
     the live model clicks the unrelated task-brief paragraph and then burns
     the rest of the slice in `NoEffectAfterAction` / `TimeoutOrHang`
     recovery. The active move is a shared history-page verification-mismatch
     cue on the exact `workflow_mutation_isolation_billing_review` rerun
   - `run-1773475880` does not yet validate or falsify that reduction: it
     regresses at the login page after a single provider call
     (`browser__type` on the username field), then idles back to a login-page
     workflow observation without reaching the queue, mutation, or history
     frontier. Treat that run as transient variance and rerun the same exact
     slice again before changing the active gap or widening the rung
   - `run-1773476023` proves the shared history-page mismatch reduction is now
     landing: after saving `T-318`, the live model opens history, sees the
     mismatch, and uses `lnk_confirmation` instead of burning the step on
     inert history clicks. The remaining miss is one page later. On the
     confirmation page the prompt still falls back to generic success framing
     even though the visible saved summary says `Ticket T-318 was routed to
     Unassigned` while the requested update targeted `Billing Review`, and the
     page still says `Saved, cross-ticket queue/history verification pending`.
     The model then burns snapshots on confirmation, returns to the queue, and
     redundantly redoes the same ticket mutation. The active move stays on the
     exact slice, but the smallest honest gap tightens further to a shared
     confirmation-page `verification_gap`
   - `run-1773476838` proves that confirmation-page reduction is now also
     landing on the live path: the model follows `lnk_confirmation` and then
     clicks `btn_reopen_ticket`. The remaining miss is after recovery starts.
     On the reopened ticket draft page, `btn_review_update` is visible but the
     prompt still falls back to a weak generic success cue, so the model
     leaves through `lnk_queue`, reopens `T-318`, and redundantly rebuilds the
     same mutation. The suite summary reports `planner_gap`, but the smaller
     shared cause is a post-reopen `recovery_gap`, so the active move is a
     generic reopened-draft resume cue before the next exact rerun
   - `run-1773477526` proves that reopened-draft reduction is now landing on
     the live path: after `btn_reopen_ticket`, the model reapplies
     `Billing Review`, `Pending Review`, and `Validate recurring invoice
     delta`, then clicks `btn_review_update`. The remaining miss is one page
     later. On the review page, `btn_confirm_update` is visible but the prompt
     still falls back to generic success framing, so the model leaves through
     `lnk_queue` before the reviewed draft is confirmed. The suite summary
     still reports `planner_gap`, but the smaller shared cause tightens again
     to a post-review `recovery_gap`, so the active move becomes a shared
     review-confirmation cue before the next exact rerun
   - `run-1773477962` does not yet validate or falsify that reduction: it
     regresses earlier on repeated `grp_login_divide_queue` no-effect clicks,
     then burns three repeated `browser__snapshot` calls after opening
     `T-318`, and never reaches the review page. Treat that run as transient
     exact variance and rerun the same exact slice again before changing the
     active gap or widening the rung
   - `run-1773478221` proves that review-confirmation reduction is now also
     landing on the live path: the model clicks `btn_review_update`,
     follows the new cue to `btn_confirm_update`, opens
     `lnk_open_audit_history`, and reaches a typed-complete `T-318` history
     page with a matching saved dispatch row. The remaining miss is one step
     later. After clicking `lnk_queue`, the queue snapshot still falls back to
     generic success framing instead of naming the remaining alternate history
     check, so the model reopens `T-318` history and confirmation rather than
     handing off to `T-310`. The smaller shared cause tightens again to a
     post-verification `recovery_gap`, so the active move becomes a shared
     queue-return alternate-history cue before the next exact rerun
   - `run-1773478557` does not yet validate or falsify that newer reduction:
     it regresses earlier on repeated `grp_login_divide_queue` no-effect
     clicks, then spends the remaining budget on form entry without reaching
     review, confirmation, or history. Treat that run as transient exact
     variance and rerun the same exact slice again before changing the active
     gap or widening the rung
   - `run-1773478729` re-opened the retained frontier one step later than
     `run-1773478221`: after returning from a verified `T-318` history page,
     the follow-up cue anchored on the case slug `REVIEW-1773478730656`
     instead of `T-318`, so the queue prompt still offered
     `lnk_history_1ebf96` and, after that reopen, the confirmation page
     further degraded to a generic `lnk_open_audit_history` loop. The smaller
     shared cause tightens again to queue-return item extraction and alternate
     link filtering, so the active move becomes a shared fix that prefers the
     concrete `/tickets/<id>/history` ticket id and only surfaces different
     item-specific history links before the next exact rerun
   - `run-1773479455` proves that follow-up fix lands on the authoritative
     live path: the exact `workflow_mutation_isolation_billing_review` rerun
     now passes judged live with provider-backed inference and full live
     artifacts present
   - `run-1773479507` immediately widens that closure to the full
     `workflow_mutation` family: both cases pass judged live with
     provider-backed inference, so the ladder advances to the next pending
     family sentinel on workflow-reorder

9. Workflow-reorder sentinel and family sweep
   Status: passed.
   Objective:
   - close the reorder sentinel and then the full `workflow_reorder` family
   Latest evidence:
   - `run-1773479677` and `run-1773479884` first established a stable
     login-stage `infra_or_bridge_gap`: browser-only workflow goals were
     coercing valid `browser__*` actions into denied `web__search`
   - exact rerun `run-1773480662` validated the bridge fix and tightened the
     remaining miss to stale post-confirm queue verification
   - exact rerun `run-1773481680` closes the sentinel live with 17 provider
     calls and full artifacts present: after confirmation the agent now
     snapshots, returns to queue, sets `Recently Updated`, refreshes, and only
     then opens `T-204` history
   - family rerun `run-1773482745` then failed judged live `1/2`; the first
     failing case, `workflow_stale_queue_reorder_billing_review`, tightened the
     smaller shared miss to refreshed-queue follow-up loss when the immediate
     prompt frame was thinner than the richer queue snapshot already in history
   - exact rerun `run-1773483141` re-closes
     `workflow_stale_queue_reorder_billing_review` with 20 provider calls and
     full artifacts present: after refresh the live model now opens visible
     distractor history `lnk_history_807ebf` instead of reopening `T-318`,
     even when the cue must be recovered from the richer earlier queue snapshot
   - full-family rerun `run-1773483313` closes the rung live: both reorder
     cases pass judged with provider-backed inference and full live artifacts
     present, confirming the reordered-queue handoff holds across the family
   Active reduction:
   - rung closed; carry the richer queue-snapshot fallback forward as retained
     generic behavior
   Exit criterion:
   - closed by `run-1773483313`

10. Stress sentinel and audit
   Status: in progress.
   Objective:
   - run `miniwob_click_collapsible_2_stress` live, then full cumulative
     `stress`
   Latest evidence:
   - exact sentinel `run-1773484611` passed judged live with provider-backed
     inference (`live_http`, `gpt-4o`, 5 calls) and full live artifacts
     present; the new exact-target handoff now grounds the visible target
     strongly enough for the live model to click it directly after section
     exploration
   - cumulative audit `run-1773484641` then failed judged live `15/19` with
     provider-backed inference and full live artifacts present. The reopened
     cases are `miniwob_click_option_core`,
     `miniwob_click_checkboxes_core`,
     `miniwob_click_checkboxes_transfer_core`, and
     `miniwob_search_engine_stress`
   - because cumulative sets are audit rungs, the first failing exact slice in
     audit order now becomes the inner-loop target: `miniwob_click_option_core`
   - exact rerun `run-1773485940` stayed red on
     `miniwob_click_option_core` with provider-backed inference and full live
     artifacts present, and it sharpened the cause to `infra_or_bridge_gap`:
     the prompt already carried the submit-turnover success cue and instructed
     `agent__complete`, while the available-tool list still omitted that
     lifecycle tool
   - exact rerun `run-1773486459` then stayed red again, but it closed that
     bridge issue live: `agent__complete` was visible and the agent used it.
     The remaining miss tightened to `planner_gap` because the model still
     clicked one radio on the next episode before completing
   - exact rerun `run-1773486774` then closed that planner miss live too: the
     agent took the correct three-step path and completed, but the persisted
     bridge state had already rolled forward to the next episode and dropped
     the successful terminal reward / termination fields
   - exact rerun `run-1773487291` closes that bridge-accounting miss live:
     the persisted bridge state now retains the completed episode's
     `raw_reward=1.0`, `terminated=true`, and original task brief strongly
     enough for the authoritative exact slice to pass even after the DOM has
     already turned over to the next episode
   Active reduction:
   - leave cumulative `stress` parked at `run-1773484641`
   - retained exact-slice reductions: submit-turnover success framing plus
     unquoted `Select X and click Submit.` target extraction now recognize
     when the post-submit snapshot belongs to the next episode; lifecycle
     tools also remain exposed across resolved intents, so the live agent can
     execute the completion path cognition names
   - latest shared reduction is now landed and exact-live proven: preserve
     MiniWoB terminal reward / raw reward / termination across the immediate
     turnover to the next episode so the suite keeps the completed benchmark
     episode instead of the reset follow-up episode
   - full cumulative `core` rerun `run-1773487386` is now done and passes
     `16/17`; the first still-red slice is `miniwob_use_autocomplete_smoke`
   - exact rerun `run-1773487838` kept
     `miniwob_use_autocomplete_smoke` red on a reusable `planner_gap`: the
     prompt already warned that autocomplete was unresolved, but the warning
     was too generic and lost to the later submit-click success cue
   - exact rerun `run-1773488542` proved the first shared autocomplete
     reduction landed, but it also showed that plain `Enter` did not commit
     the suggestion; the browser key result still carried unresolved
     autocomplete state
   - latest shared reduction is now exact-live proven by `run-1773489181`:
     when the widget is open with a single grounded suggestion but no evidence
     of a highlighted candidate, prompt the generic recovery as
     `ArrowDown` then `Enter`; only use `Enter` directly once a highlighted
     candidate is grounded. The same reduction also suppresses misleading
     submit-success framing while autocomplete remains unresolved
   - exact autocomplete closure `run-1773489181` is now done and green, so
     the rung widened immediately to full cumulative `core`
   - full cumulative `core` rerun `run-1773489311` has now finished judged
     live `13/17`
   - the first exact red slice in family order has moved to
     `miniwob_click_tab_smoke`
   - the smallest honest class has also tightened to `infra_or_bridge_gap`:
     `error.txt` now shows intermittent `launch Chromium for agent mode`
     failures where the browser exits before the websocket URL is resolved
   - sibling launch-path failures are already visible on
     `miniwob_scroll_text_direction_smoke`,
     `miniwob_click_checkboxes_core`, and `miniwob_focus_text_2_core`, so the
     next fix should target shared browser-start recovery rather than any
     benchmark-local behavior
   - collapse immediately to the exact live rerun of
     `miniwob_click_tab_smoke`
   - exact rerun `run-1773489982` is now green with provider-backed
     inference and full live artifacts present, so the first launch-blocked
     slice is re-closed
   - widened family rerun `run-1773490053` is now green at `17/17`, so the
     shared launch-instability branch is closed on the authoritative live
     path
   - cumulative `stress` rerun `run-1773490463` is now in flight on the
     authoritative live path
   - every previously reopened `core`-derived case is already green again in
     that in-flight stress audit through `miniwob_click_button_sequence_core`
   - if the stress audit reopens, collapse immediately to the first exact red
     slice in family order; if it closes, rung 10 is done

## Iteration Update Protocol

For every iteration:

1. Update `Status` and `Benchmark Escalation Ladder` first.
2. Stay on the active family until it reaches parity, plateaus, or hard-blocks.
3. Keep the inner loop simple:
   - run the current sentinel or exact failing case
   - fix the smallest shared cause
   - rerun the exact same live slice
   - only then widen to the full family
4. Treat cumulative sets (`core`, `stress`) as audit rungs, not the per-fix dev
   loop.
5. Record:
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
9. Do not let this document become a changelog; keep only the rolling window
   needed for the next agent to continue correctly.

Decision rule:

- the program succeeds by improving generic computer-use capability through live
  benchmark failures, not by teaching the system to overfit benchmark-specific
  judges
