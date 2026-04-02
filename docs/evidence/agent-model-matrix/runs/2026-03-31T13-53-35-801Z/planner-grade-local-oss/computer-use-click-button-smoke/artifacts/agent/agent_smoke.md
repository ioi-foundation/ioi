# Computer Use Suite

- mode: `agent`
- task_set: `smoke`
- passing: `0` / `1`
- artifact_root: `/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/agent-model-matrix/runs/2026-03-31T13-53-35-801Z/planner-grade-local-oss/computer-use-click-button-smoke/artifacts`
- support_counts: `{"infra_blocked":1}`
- gap_counts: `{"infra_or_bridge_gap":1}`

| case | env | backend | pass | support | gap | tags | reward | terminated | failure |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| miniwob_click_button_smoke | click-button | live_http | no | infra_blocked | infra_or_bridge_gap |  | -1.000 | true | ERROR_CLASS=NoEffectAfterAction Browser click/focus failed to satisfy postcondition for '#area > button:nth-of-type(2)'. verify={"click_errors":[],"fallback_used":"selector_focus","location_shortcut_sent":false,"post":{"blocked_by":"#sync-task-cover","editable":false,"focused":true,"found":true,"role":"","tag":"button","topmost":false,"url":"file:///tmp/ioi-miniwob-bridge/ef4de10f4591e3c0/miniwob/click-button.1.html","visible":true},"postcondition_met":false,"pre":{"blocked_by":"#sync-task-cover","editable":false,"focused":false,"found":true,"role":"","tag":"button","topmost":false,"url":"file:///tmp/ioi-miniwob-bridge/ef4de10f4591e3c0/miniwob/click-button.1.html","visible":true},"selector":"#area > button:nth-of-type(2)"} |