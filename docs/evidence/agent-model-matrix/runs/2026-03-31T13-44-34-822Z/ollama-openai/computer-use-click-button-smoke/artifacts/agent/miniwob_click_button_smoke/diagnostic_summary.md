# MiniWoB Case Diagnostic

## Summary
- case_dir: `/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/agent-model-matrix/runs/2026-03-31T13-44-34-822Z/ollama-openai/computer-use-click-button-smoke/artifacts/agent/miniwob_click_button_smoke`
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
- final_last_event: `click target=#area > button:nth-of-type(1) x=0 y=0 at=1774964708649`
- sync_count: `6`
- query_text: `Click on the "Okay" button.`

## Final Surface
- visible_text_excerpt: `Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: -1.00 Last 10 average: -1.00 Time left: - Episodes done: 1 START`
- page_url: `file:///tmp/ioi-miniwob-bridge/7ba12cc3a85c608b/miniwob/click-button.1.html`

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
- bootstrap_sync_ms: `1774964708071`
- browser_launch_started_at_ms: `1774964693633`
- browser_launch_finished_at_ms: `1774964707817`
- session_created_at_ms: `1774964707964`
- browser_navigation_started_at_ms: `1774964707964`
- browser_navigation_finished_at_ms: `1774964708096`
- initial_bridge_ready_observed_at_ms: `1774964708097` (+26 ms from bootstrap)
- first_step_service_started_at_ms: `1774964708635` (+564 ms from bootstrap)
- first_inference_started_at_ms: `1774964708098` (+27 ms from bootstrap)
- first_inference_finished_at_ms: `1774964708634` (+563 ms from bootstrap)
- first_bridge_input_event_ms: `1774964708649` (+578 ms from bootstrap)
- first_grounded_target_event_ms: `1774964708649` (+578 ms from bootstrap)
- terminal_sync_ms: `1774964708651` (+580 ms from bootstrap)
- first_step_service_finished_at_ms: `1774964708805` (+734 ms from bootstrap)
- case_finished_at_ms: `1774964708807` (+736 ms from bootstrap)
- first_inference_tool: `browser__click`
- first_inference_elapsed_ms: `536`
- bootstrap_to_first_inference_start_ms: `27`
- bootstrap_to_first_grounded_target_ms: `578`
- first_grounded_target_to_terminal_ms: `2`
- terminal_to_step_finish_tail_ms: `154`

## Inference Calls
- call 1: method=chat_completions_tool_call start=1774964708098 finish=1774964708634 elapsed=536 tool=browser__click
  source=computer_use_suite.harness.agent
  arguments={"selector": "#area > button:nth-of-type(1)"}

## Step Outcome Matrix
- unavailable

## Execution Receipts
- unavailable

## Bridge Sync History
- sync 0 @ 1774964708071: trigger=bootstrap step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 1 @ 1774964708191 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body flags=trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 2 @ 1774964708311 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 3 @ 1774964708431 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 4 @ 1774964708551 (+120 ms): trigger=heartbeat step=0 reward=0.0 raw_reward=0.0 terminated=False truncated=False interactive=7 scroll_targets=0 dom=24 focus=body excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: - Last 10 average: - Time left: 10 / 10sec Episodes do..."
- sync 5 @ 1774964708651 (+100 ms): trigger=end_episode step=1 reward=-1.0 raw_reward=-1.0 terminated=True truncated=False interactive=7 scroll_targets=0 dom=25 focus=body last_event=click target=#area > button:nth-of-type(1) x=0 y=0 at=1774964708649 flags=reward_change,termination_change,surface_change,trigger_change excerpt="Click on the "Okay" button. neque et adipiscing proin ac nulla dictum amet facilisis Previous eu id non: Okay Last reward: -1.00 Last 10 average: -1.00 Time left: - Episodes don..."

## Agent Timeline
