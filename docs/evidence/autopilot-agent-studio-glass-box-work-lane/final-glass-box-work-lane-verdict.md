# Autopilot Agent Studio Glass Box Work Lane Verdict

Status: `glass_box_work_lane_target_proven`

Generated: 2026-06-01T20:06:24-04:00

## Verdict

The Agent Studio glass-box work lane target is proven against the live GUI evidence in:

- `docs/evidence/autopilot-agent-studio-glass-box-work-lane/2026-06-01T23-50-01-529Z`
- `docs/evidence/autopilot-agent-studio-glass-box-work-lane/glass-box-work-lane-final-manifest.json`

The final proof run completed all required product scenarios, captured before/active/expanded/final states, preserved the VS Code/OpenVSCode workbench look, and recorded cleanup proof with no remaining orphan processes.

## Acceptance Results

| Requirement | Verdict | Evidence |
| --- | --- | --- |
| Collapsed completed work shows only `Worked for Xs` | `ux_parity_pass` | `proof.json`, `work-lane-expanded-00.png` through `work-lane-expanded-05.png` |
| Expanded work reveals readable chronological work lane | `ux_parity_pass` | `work-lane-expanded-00.png` through `work-lane-expanded-05.png` |
| Tool rows show observable work | `ux_parity_pass` | `proof.json` query `workLaneProof.rowLabels` |
| Web rows include source chips, titles, domains, excerpts, and state | `source_rich_pass` | `work-lane-expanded-00.png`, `proof.json` `sourceRowsProof` |
| Thought preview streams while active without hidden chain-of-thought | `thought_preview_pass` | `pending-worklog-live.png`, `proof.json` `pendingProjectionProof` |
| Provider reasoning remains distinct from runtime thought preview | `live_pass` | `proof.json`, runtime trace summary |
| Final answers stream and render markdown | `markdown_pass` | `agent-final-handoff-stream-live.png`, `proof.json` `markdownRenderProof` |
| Artifact/source streaming works | `artifact_pass` | `conversation-artifact-compact.png`, `conversation-artifact-expanded.png`, `conversation-artifact-action-state.png`, `conversation-artifact-promoted-state.png` |
| Browser/computer work appears as managed session artifacts | `browser_session_pass` | `managed-session-compact.png`, `managed-session-expanded-observe.png`, `managed-session-take-over.png`, `managed-session-returned-to-agent.png` |
| Raw internals stay out of product chat | `live_pass` | `proof.json`, `console-logs.json`, leak audit in final manifest |
| Cleanup after live GUI scenario | `live_pass` | `process-cleanup-after-run.json`, `workspace-fixture-cleanup.json`, `user-workspace-fixture-cleanup.json` |

## Live Product Matrix

The live GUI run exercised the required scenarios:

- `Which is a better investment right now, Akash or Filecoin?`
- `Create a website that explains post-quantum computers.`
- `Create an HTML file about photonic quantum computing and use sources.`
- `Call some tools and explore this repository, then summarize what you learned.`
- `Fix this failing test in the disposable repo and show me the patch.`
- `Open a sandbox browser, inspect this fixture page, and summarize what changed.`

The run observed successful model-backed streaming, artifact source streaming, final handoff streaming, markdown hydration, source-rich web rows, managed browser session controls, and conversation artifact embeds.

## Fixes Made

- Preserved and projected managed browser/computer session cards through the public work-record boundary.
- Added live conversation artifact card projection for compact and expanded deliverables during streaming turns.
- Added source-chip favicon support with host-side and webview-side URL sanitizers.
- Sanitized product handoff text so fixture labels and internal tool-call wording stay in trace/evidence instead of chat.
- Hardened static UI guards for source chips, sanitizer availability, managed session rendering, and artifact projection.

## Leak Audit

Final status:

- `hidden_cot_leak`: false
- `trace_leak`: false
- `raw_payload_leak`: false
- `fixture_leak`: false
- `console_error_count`: 0

Trace details, receipts, raw payloads, daemon events, route internals, fixture paths, and full logs remain in evidence/tracing files, not the product chat transcript.

## Validation

Supporting checks passed:

- `cargo fmt --package ioi-services`
- `cargo test -p ioi-services product_handoff --lib`
- `cargo test -p ioi-services sanitizes_queue_agent_complete_product_fixture_labels --lib`
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs`
- `AUTOPILOT_AGENT_STUDIO_MASTER_GUIDE=.internal/plans/autopilot-agent-studio-glass-box-work-lane-master-guide.md AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT=docs/evidence/autopilot-agent-studio-glass-box-work-lane AUTOPILOT_AGENT_STUDIO_UPDATE_GUIDE=0 node scripts/run-autopilot-agent-studio-live-gui-validation.mjs --run --scenario glass-box-work-lane-live`

## Cleanup

Cleanup proof:

- `process-cleanup-after-run.json`: `ok: true`, `after: []`, `orphanProcesses: []`
- `workspace-fixture-cleanup.json`: fixture removed
- `user-workspace-fixture-cleanup.json`: fixture removed

## Remaining Blockers

None.
