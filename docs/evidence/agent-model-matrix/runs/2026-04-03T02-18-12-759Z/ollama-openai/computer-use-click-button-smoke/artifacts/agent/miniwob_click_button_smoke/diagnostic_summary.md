# MiniWoB Case Diagnostic

## Summary
- case_dir: `/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/agent-model-matrix/runs/2026-04-03T02-18-12-759Z/ollama-openai/computer-use-click-button-smoke/artifacts/agent/miniwob_click_button_smoke`
- env_id: `click-button`
- model: `llama3.2:3b`
- backend: `live_http`
- provider_calls: `1`
- reward: `-1.0`
- raw_reward: `-1.0`
- terminated: `True`
- truncated: `False`
- episode_step: `1`
- final_trigger: `end_episode`
- final_last_event: `click target=#area > button:nth-of-type(1) x=0 y=0 at=1775182832025`
- sync_count: `6`
- query_text: `Click on the "Okay" button.`

## Final Surface
- visible_text_excerpt: `Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: -1.00 Last 10 average: -1.00 Time left: - Episodes done: 1 START`
- page_url: `file:///tmp/ioi-miniwob-bridge/765e6cd5bac3e7d6/miniwob/click-button.1.html`

## Findings
- no automatic findings

### Interactive Elements
- button | selector=#area > button:nth-of-type(1) | text=Previous
- input | selector=#area > input
- button | selector=#area > button:nth-of-type(2) | text=Okay
- label | selector=#reward-display > div:nth-of-type(1) > label | text=Last reward:
- label | selector=#reward-display > div:nth-of-type(2) > label | text=Last 10 average:
- label | selector=#reward-display > div:nth-of-type(3) > label | text=Time left:
- label | selector=#reward-display > div:nth-of-type(4) > label | text=Episodes done:

## Phase Timing
- bootstrap_sync_ms: `1775182831460`
- browser_launch_started_at_ms: `1775182816369`
- browser_launch_finished_at_ms: `1775182831213`
- session_created_at_ms: `1775182831355`
- browser_navigation_started_at_ms: `1775182831355`
- browser_navigation_finished_at_ms: `1775182831481`
- initial_bridge_ready_observed_at_ms: `1775182831482` (+22 ms from bootstrap)
- first_step_service_started_at_ms: `1775182832016` (+556 ms from bootstrap)
- first_inference_started_at_ms: `1775182831483` (+23 ms from bootstrap)
- first_inference_finished_at_ms: `1775182832015` (+555 ms from bootstrap)
- first_bridge_input_event_ms: `1775182832025` (+565 ms from bootstrap)
- first_grounded_target_event_ms: `1775182832025` (+565 ms from bootstrap)
- terminal_sync_ms: `1775182832027` (+567 ms from bootstrap)
- first_step_service_finished_at_ms: `1775182832180` (+720 ms from bootstrap)
- case_finished_at_ms: `1775182832181` (+721 ms from bootstrap)
- first_inference_tool: `browser__click`
- first_inference_elapsed_ms: `532`
- bootstrap_to_first_inference_start_ms: `23`
- bootstrap_to_first_grounded_target_ms: `565`
- first_grounded_target_to_terminal_ms: `2`
- terminal_to_step_finish_tail_ms: `153`

## Inference Calls
- call 1: method=chat_completions_tool_call start=1775182831483 finish=1775182832015 elapsed=532 tool=browser__click
  source=computer_use_suite.harness.agent
  arguments={"selector": "#area > button:nth-of-type(1)"}

## Step Outcome Matrix
- unavailable

## Execution Receipts
- unavailable

## Bridge Sync History
- sync 0 @ 1775182831460: trigger=bootstrap step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 1 @ 1775182831580 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 2 @ 1775182831700 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 3 @ 1775182831820 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 4 @ 1775182831940 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 5 @ 1775182832027 (+87 ms): trigger=end_episode step=1 reward=-1.0 raw_reward=-1.0 terminated=True truncated=False interactive=7 scroll_targets=0 dom=25 focus=body last_event=click target=#area > button:nth-of-type(1) x=0 y=0 at=1775182832025 flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: -1.00 Last 10 average: -1.00 Time left: - Episodes don..."

## Agent Timeline
