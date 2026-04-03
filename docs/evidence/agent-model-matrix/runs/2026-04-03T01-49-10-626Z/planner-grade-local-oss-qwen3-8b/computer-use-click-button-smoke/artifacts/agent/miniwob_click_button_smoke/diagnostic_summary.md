# MiniWoB Case Diagnostic

## Summary
- case_dir: `/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/agent-model-matrix/runs/2026-04-03T01-49-10-626Z/planner-grade-local-oss-qwen3-8b/computer-use-click-button-smoke/artifacts/agent/miniwob_click_button_smoke`
- env_id: `click-button`
- model: `qwen3:8b`
- backend: `live_http`
- provider_calls: `1`
- reward: `0.6931`
- raw_reward: `1.0`
- terminated: `True`
- truncated: `False`
- episode_step: `1`
- final_trigger: `end_episode`
- final_last_event: `click target=#area > button:nth-of-type(2) x=0 y=0 at=1775181025968`
- sync_count: `27`
- query_text: `Click on the "Okay" button.`

## Final Surface
- visible_text_excerpt: `Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: 0.69 Last 10 average: 0.69 Time left: - Episodes done: 1 START`
- page_url: `file:///tmp/ioi-miniwob-bridge/0e29faa715031eef/miniwob/click-button.1.html`

## Findings
- First grounded target arrived only after 3068 ms from bootstrap.

### Interactive Elements
- button | selector=#area > button:nth-of-type(1) | text=Previous
- input | selector=#area > input
- button | selector=#area > button:nth-of-type(2) | text=Okay
- label | selector=#reward-display > div:nth-of-type(1) > label | text=Last reward:
- label | selector=#reward-display > div:nth-of-type(2) > label | text=Last 10 average:
- label | selector=#reward-display > div:nth-of-type(3) > label | text=Time left:
- label | selector=#reward-display > div:nth-of-type(4) > label | text=Episodes done:

## Phase Timing
- bootstrap_sync_ms: `1775181022900`
- browser_launch_started_at_ms: `1775181005952`
- browser_launch_finished_at_ms: `1775181022650`
- session_created_at_ms: `1775181022796`
- browser_navigation_started_at_ms: `1775181022796`
- browser_navigation_finished_at_ms: `1775181022920`
- initial_bridge_ready_observed_at_ms: `1775181022922` (+22 ms from bootstrap)
- first_step_service_started_at_ms: `1775181025960` (+3060 ms from bootstrap)
- first_inference_started_at_ms: `1775181022924` (+24 ms from bootstrap)
- first_inference_finished_at_ms: `1775181025959` (+3059 ms from bootstrap)
- first_bridge_input_event_ms: `1775181025968` (+3068 ms from bootstrap)
- first_grounded_target_event_ms: `1775181025968` (+3068 ms from bootstrap)
- terminal_sync_ms: `1775181025970` (+3070 ms from bootstrap)
- first_step_service_finished_at_ms: `1775181026120` (+3220 ms from bootstrap)
- case_finished_at_ms: `1775181026122` (+3222 ms from bootstrap)
- first_inference_tool: `browser__click`
- first_inference_elapsed_ms: `3035`
- bootstrap_to_first_inference_start_ms: `24`
- bootstrap_to_first_grounded_target_ms: `3068`
- first_grounded_target_to_terminal_ms: `2`
- terminal_to_step_finish_tail_ms: `150`

## Inference Calls
- call 1: method=chat_completions_tool_call start=1775181022924 finish=1775181025959 elapsed=3035 tool=browser__click
  source=computer_use_suite.harness.agent
  arguments={"selector": "#area > button:nth-of-type(2)"}

## Step Outcome Matrix
- unavailable

## Execution Receipts
- unavailable

## Bridge Sync History
- sync 0 @ 1775181022900: trigger=bootstrap step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 1 @ 1775181023020 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 2 @ 1775181023140 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 3 @ 1775181023260 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 4 @ 1775181023380 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 5 @ 1775181023500 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 6 @ 1775181023620 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 7 @ 1775181023740 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 8 @ 1775181023860 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 9 @ 1775181023980 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=surface_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 10 @ 1775181024100 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 11 @ 1775181024220 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 12 @ 1775181024340 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 13 @ 1775181024460 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 14 @ 1775181024580 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 15 @ 1775181024700 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 16 @ 1775181024820 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 17 @ 1775181024940 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=surface_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 18 @ 1775181025060 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 19 @ 1775181025180 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 20 @ 1775181025300 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 21 @ 1775181025420 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 22 @ 1775181025540 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 23 @ 1775181025660 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 24 @ 1775181025780 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 8 / 10sec Episodes don..."
- sync 25 @ 1775181025900 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=surface_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 7 / 10sec Episodes don..."
- sync 26 @ 1775181025970 (+70 ms): trigger=end_episode step=1 reward=0.6931 raw_reward=1.0 terminated=True truncated=False interactive=7 scroll_targets=0 dom=25 focus=body last_event=click target=#area > button:nth-of-type(2) x=0 y=0 at=1775181025968 flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: 0.69 Last 10 average: 0.69 Time left: - Episodes done:..."

## Agent Timeline
