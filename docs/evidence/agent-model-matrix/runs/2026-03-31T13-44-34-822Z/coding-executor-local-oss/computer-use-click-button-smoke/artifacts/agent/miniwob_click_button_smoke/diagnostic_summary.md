# MiniWoB Case Diagnostic

## Summary
- case_dir: `/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/agent-model-matrix/runs/2026-03-31T13-44-34-822Z/coding-executor-local-oss/computer-use-click-button-smoke/artifacts/agent/miniwob_click_button_smoke`
- env_id: `click-button`
- model: `qwen2.5:7b`
- backend: `live_http`
- provider_calls: `1`
- reward: `0.8822`
- raw_reward: `1.0`
- terminated: `True`
- truncated: `False`
- episode_step: `1`
- final_trigger: `end_episode`
- final_last_event: `click target=#area > button:nth-of-type(2) x=0 y=0 at=1774965041664`
- sync_count: `11`
- query_text: `Click on the "Okay" button.`

## Final Surface
- visible_text_excerpt: `Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: 0.88 Last 10 average: 0.88 Time left: - Episodes done: 1 START`
- page_url: `file:///tmp/ioi-miniwob-bridge/d0ba105c5242bc79/miniwob/click-button.1.html`

## Findings
- First grounded target arrived only after 1178 ms from bootstrap.

### Interactive Elements
- button | selector=#area > button:nth-of-type(1) | text=Previous
- input | selector=#area > input
- button | selector=#area > button:nth-of-type(2) | text=Okay
- label | selector=#reward-display > div:nth-of-type(1) > label | text=Last reward:
- label | selector=#reward-display > div:nth-of-type(2) > label | text=Last 10 average:
- label | selector=#reward-display > div:nth-of-type(3) > label | text=Time left:
- label | selector=#reward-display > div:nth-of-type(4) > label | text=Episodes done:

## Phase Timing
- bootstrap_sync_ms: `1774965040486`
- browser_launch_started_at_ms: `1774965025932`
- browser_launch_finished_at_ms: `1774965040238`
- session_created_at_ms: `1774965040382`
- browser_navigation_started_at_ms: `1774965040382`
- browser_navigation_finished_at_ms: `1774965040512`
- initial_bridge_ready_observed_at_ms: `1774965040515` (+29 ms from bootstrap)
- first_step_service_started_at_ms: `1774965041651` (+1165 ms from bootstrap)
- first_inference_started_at_ms: `1774965040518` (+32 ms from bootstrap)
- first_inference_finished_at_ms: `1774965041650` (+1164 ms from bootstrap)
- first_bridge_input_event_ms: `1774965041664` (+1178 ms from bootstrap)
- first_grounded_target_event_ms: `1774965041664` (+1178 ms from bootstrap)
- terminal_sync_ms: `1774965041666` (+1180 ms from bootstrap)
- first_step_service_finished_at_ms: `1774965041821` (+1335 ms from bootstrap)
- case_finished_at_ms: `1774965041824` (+1338 ms from bootstrap)
- first_inference_tool: `browser__click`
- first_inference_elapsed_ms: `1132`
- bootstrap_to_first_inference_start_ms: `32`
- bootstrap_to_first_grounded_target_ms: `1178`
- first_grounded_target_to_terminal_ms: `2`
- terminal_to_step_finish_tail_ms: `155`

## Inference Calls
- call 1: method=chat_completions_tool_call start=1774965040518 finish=1774965041650 elapsed=1132 tool=browser__click
  source=computer_use_suite.harness.agent
  arguments={"selector": "#area > button:nth-of-type(2)"}

## Step Outcome Matrix
- unavailable

## Execution Receipts
- unavailable

## Bridge Sync History
- sync 0 @ 1774965040486: trigger=bootstrap step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 1 @ 1774965040606 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 2 @ 1774965040726 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 3 @ 1774965040846 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 4 @ 1774965040966 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 5 @ 1774965041086 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 6 @ 1774965041206 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 7 @ 1774965041326 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 8 @ 1774965041446 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 9 @ 1774965041566 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=surface_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 9 / 10sec Episodes don..."
- sync 10 @ 1774965041666 (+100 ms): trigger=end_episode step=1 reward=0.8822 raw_reward=1.0 terminated=True truncated=False interactive=7 scroll_targets=0 dom=25 focus=body last_event=click target=#area > button:nth-of-type(2) x=0 y=0 at=1774965041664 flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: 0.88 Last 10 average: 0.88 Time left: - Episodes done:..."

## Agent Timeline
