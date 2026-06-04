# Agent Runtime Parity Plus Refactor And Intuitiveness Report

Date: 2026-06-03

Scope: first refactor leg after the parity-plus audit guide. This pass prioritized behavior-preserving extractions that improve ownership boundaries without changing public command ids, request/response envelopes, data-testids, retry-limit semantics, or generated evidence handling.

## Completed Splits

### Live GUI Proof Harness

- Added `scripts/lib/live-gui-proof-harness/` with shared process, network, bridge, file, Playwright, screenshot, and cleanup helpers.
- Migrated Stage 8 managed-session reconnect proof and Stage 9 historic replay proof to the shared harness.
- Moved Stage 8/Stage 9 workbench bridge `/state`, `/commands`, and `/requests` server boilerplate into shared harness bridge helpers while preserving the public bridge envelopes.
- Added checked-in Stage 9 replay fixtures so the live replay proof can run from a clean checkout without relying on ignored `docs/evidence` artifacts.
- Hardened the Stage 8 managed-session control click path to reacquire the Studio webview frame/card across VS Code webview swaps.
- Renamed the Stage 8 synthetic browser card from a spoof-like login-gate label to a manual authentication handoff fixture so the proof reads as operator-control state, not a fake approval surface.
- Renamed lingering private test/proof fixture ids and reasons from `login_gate` to `manual_auth_handoff`; public data-testids and response envelopes are unchanged.
- Kept generated proof outputs ignored under `docs/evidence/`.

### Agent Studio Workbench Extension

- Added `apps/autopilot/openvscode-extension/ioi-workbench/bridge/client.js` for daemon endpoint/token/base-url and JSON request helpers.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/public-text-sanitizer.js` for product-facing assistant/tool text sanitization.
- Replaced remaining Studio public-text sanitizer pass-through wrappers in `extension.js` with direct destructured helpers from the sanitizer factory.
- Replaced pure Studio work-summary and model-completion pass-through wrappers in `extension.js` with direct named helper imports/destructuring while leaving projection-aware composition local.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/model-completion.js` to own SSE payload parsing, Studio stream metadata projection, provider timing usage shaping, and daemon SSE request construction.
- Added focused model-completion tests for SSE frame parsing, text/reasoning delta aliases, receipt de-duping, provider timing usage projection, and stop-reason propagation.
- Hardened Studio stream receipt collection to drop absent receipt aliases before de-duping, avoiding bogus `"undefined"` receipt rows in product projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js` for the initial Agent Studio runtime projection shape.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/migration.js` for migration-assistant command registration.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/models.js`.
- Moved Models command registration out of `extension.js` while preserving public `ioi.models.*` command ids, daemon model-workbench action envelopes, catalog source/download envelopes, and model-to-workflow binding behavior.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/navigation.js`.
- Moved Autopilot overview, command center, code-mode, back-navigation, Agent Studio open, Agent Builder, and Studio composer-focus command registration out of `extension.js` while preserving public `ioi.overview.open`, `ioi.commandCenter.open`, `ioi.code.open`, `ioi.autopilot.back`, `ioi.studio.open`, `ioi.studio.agentBuilder`, and `ioi.studio.focusComposer` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/runtime-surfaces.js`.
- Moved runs, policy, artifact drill-in, connector, and governed browser/computer-use command registration out of `extension.js` while preserving public `ioi.runs.*`, `ioi.policy.open`, `ioi.artifacts.openEvidence`, `ioi.artifacts.openPolicy`, `ioi.chatSession.openArtifact`, `ioi.connections.*`, and `ioi.automation.browser` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/quick-input.js` for fork-native QuickInput handoff commands.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/chat.js`.
- Moved IOI Chat command registration and artifact-review chat handoff registration out of `extension.js` while preserving public `ioi.chat.*` and `ioi.artifacts.review` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-quick-input.js`.
- Moved Agent Studio native context/tool QuickPick command registration out of `extension.js` while preserving `ioi.studio.openContextPicker` and `ioi.studio.openToolPicker` command ids and bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-mode-controls.js`.
- Moved Agent Studio permission-mode picker, execution-mode application, and permission-mode application command registration out of `extension.js` while preserving `ioi.quickInput.permissionMode.pick`, `ioi.studio.applyAgentMode`, and `ioi.studio.applyPermissionMode` command ids and daemon-owned permission bridge envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/workflow.js`.
- Moved Workflow Composer command registration out of `extension.js` while preserving public `ioi.workflow.*` command ids, workflow compositor bridge envelopes, and proposal-first code-generation request shape.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-managed-sessions.js` for managed browser/computer session projection, daemon inspection application, and reconnect proof bridge reporting.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-replay.js` for replay-step projection from runtime events and receipts.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-test-hooks.js` for parity-plus/test-hook command registration while preserving public command ids.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/context-snapshot.js` for workbench context snapshots, SCM/task state, diagnostics, and inspection-target index projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/modes.js`.
- Moved Agent Studio Ask/Agent execution-mode and permission-mode normalization, labels, option rows, thread-mode mapping, and daemon mapping out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio mode pass-through wrappers and duplicated mode constants in `extension.js` with direct named imports from `studio/modes.js`.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/source-refs.js`.
- Moved Studio runtime-event JSON parsing, partial JSON source recovery, source-chip normalization, source-reference traversal, and excerpt selection out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio source-reference pass-through wrappers and stale local compatibility-key constant in `extension.js` with direct named imports from `studio/source-refs.js`.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-intent.js`.
- Moved Studio artifact/canvas prompt classification, local intent-frame fallback routing, artifact class/title/summary derivation, and intent-frame payload projection out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio artifact-intent pass-through wrappers in `extension.js` with direct destructured helpers from the artifact-intent factory.
- Added focused artifact-intent tests for generated website artifacts, browser observation captures, Ask-mode routing, runtime-cockpit routing, injected retrieval/workspace predicates, and snake/camel payload normalization.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-preview.js`.
- Moved Studio conversation artifact class labels, output modality detection, preview label/srcdoc shaping, inline preview rendering, and artifact row HTML out of `extension.js` behind compatibility wrappers.
- Replaced the remaining Studio artifact-preview pass-through wrappers in `extension.js` with direct destructured helpers from the artifact-preview factory.
- Added focused artifact-preview tests for website/generic labels, media-type preview labels, CSP nonce injection, source preview escaping, and stable artifact row data-testids.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/managed-session-view.js`.
- Replaced the remaining Studio managed-session-view pass-through wrappers in `extension.js` with direct destructured helpers from the managed-session-view factory.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/pending-work.js`.
- Moved Studio pending-work filtering, concrete tool row normalization, command-output excerpt projection, pending worklog upsert/de-dupe behavior, runtime-event pending-step projection, runtime-event seen-id tracking, and tool-label mapping out of `extension.js`.
- Added focused pending-work tests for abstract row filtering, command-output redaction/preservation, row update behavior, runtime-event projection, source chips, and seen-id de-duping.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/work-record-projection.js`.
- Moved sanitized command-output projection, workspace-path bounding, command label/status shaping, diff-hunk projection, command/work-row duplicate filtering, and public work-record webview projection out of `extension.js`.
- Added focused work-record projection tests for command trace/path redaction, workspace-relative hunk paths, generic command-row filtering, richer command output preservation, managed-session passthrough, and public output redaction.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/response-metrics.js`.
- Moved Studio response token/latency metrics projection, response-metrics rows, reasoning split, thinking rows, answer content rows, and receipt-backed verified badge rendering out of `extension.js`.
- Added focused response-metrics tests for provider usage aliases, estimated token fallback, escaped metrics HTML, thinking extraction, verified/pending badge rendering, and response usage alias projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/source-chip-renderer.js`.
- Moved Studio answer-source footer rendering, source-chip URL/icon sanitization, favicon fallback selection, chip HTML rendering, and direct/artifact source de-duping out of `extension.js`.
- Added focused source-chip renderer tests for URL sanitation, explicit and fallback favicon handling, safe anchor/span rendering, escaped labels, duplicate source removal, and fallback icon data URIs.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/code-execution.js`.
- Moved Studio fenced-code extraction, plan-only code execution policy classification, and chat code-execution card rendering out of `extension.js`.
- Added focused code-execution tests for executable fence language aliases, network/host-write blocking, plan-only payload projection, disabled blocked actions, and empty non-executable turns.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/native-chat-view.js`.
- Moved native OpenVSCode chat pane icon rendering, turn normalization, conversation rendering, and chat-view rendering out of `extension.js`.
- Added focused native chat view tests for default actions, inspection targets, escaped turns/status, configured labels, and icon fallbacks.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/tool-palette.js`.
- Moved Agent Studio tool/context QuickPick item shaping, tool palette sections, built-in tool rows, and live/runtime catalog fallbacks out of `extension.js`.
- Added focused tool-palette tests for row alias normalization, stable fallback sections, separator/icon projection, and context bridge request affordances.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/model-selection.js`.
- Moved Agent Studio product model selection filtering, fixture/external provider gates, reasoning-effort controls, output-token bounds, preferred model selection, Studio model snapshot projection, and mounted-model QuickPick rows out of `extension.js`.
- Moved product model selection list and loaded product model instance projection out of `extension.js` so overview counts share the same model-selection policy module.
- Moved Studio route-invocation model id resolution out of `extension.js` into `model-selection.js`, preserving explicit model ids, concrete model route aliases, `route.*` auto fallback, and fixture-model rejection.
- Added focused model-selection tests for fixture/external/embedding-only rejection, injected environment gates, reasoning/token controls, active route preference, mounted model QuickPick projection, selection de-duping, and loaded-instance filtering.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/model-fixture-policy.js`.
- Moved Studio fixture-model environment gating, deny-fixture policy envelope shaping, and fixture-marker detection out of `extension.js` while preserving model-selection injection and artifact generation policy behavior.
- Added focused model-fixture-policy tests for fixture env aliases, deny-policy shape, and fixture marker vocabulary.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/overview-view.js`.
- Moved Autopilot Overview tone mapping, status pill rendering, action button rendering, and overview row rendering out of `extension.js`.
- Added focused overview-view tests for tone classes, escaping, and command payload affordances.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/trace-view.js`.
- Moved Studio trace visibility classification, trace target/link construction, trace item flattening, and focused trace selection out of `extension.js`.
- Moved Runs/Tracing evidence-console rendering, focused trace panels, proof-export posture, and trace row bucketing out of `extension.js`.
- Added focused trace-view tests for visibility classes, daemon trace payload affordances, projection flattening, receipt-based focus fallback, and rendered tracing-surface separation.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/view-helpers.js`.
- Moved shared view helpers for relative time labels, command payload attributes, command buttons, item stacks, runtime summary strips, and bridge diagnostics out of `extension.js`.
- Added focused view-helper tests for compact time labels, payload escaping, command affordances, item stacks, runtime summary rows, and diagnostics escaping.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/value-helpers.js`.
- Moved Studio `stringValue` and `firstArray` helpers out of `extension.js` while preserving the extension's existing trim/fallback semantics.
- Moved managed browser/computer session work-record attachment and card row rendering out of `extension.js` behind compatibility wrappers.
- Added focused managed-session view tests for bounded session-card attachment, waiting-for-user handoff rendering, control-state data-testids, HTML escaping, and default sandbox browser state.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/durability-panels.js`.
- Moved Studio session-brain and trajectory-replay proof panel projection out of `extension.js` while preserving the existing test-hook command flow, bridge request envelopes, and product panel data-testids.
- Added focused durability-panel tests for required run-brain artifacts, receipt linking, read-only audit state, workspace-boundary projection, stable trajectory replay ids, cursor replay emptiness, and duplicate side-effect blocking.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/policy-lease-lifecycle.js`.
- Moved Studio policy-lease lifecycle fixture materialization, approval-required tool body shaping, and allow/revoke/expiry row projection out of `extension.js` while preserving the live daemon exercise command and bridge request envelope.
- Added focused policy-lease lifecycle tests for fixture path materialization, daemon approval envelope fields, dry-run patch payloads, allow-once execution, revoke blocking, expiry blocking, and receipt propagation.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/chat-output-renderers.js`.
- Moved Studio Mermaid chat-output renderer source extraction, summary projection, toolbar/source HTML, clickable-node projection, and verified renderer badge integration out of `extension.js`.
- Added focused chat-output renderer tests for fenced Mermaid extraction, existing node/edge summary behavior, stable renderer controls/data-testids, verified receipt badge propagation, and explicit renderer-card preference.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/parity-plus-panels.js`.
- Moved Studio parity-plus panel shell rendering, session-brain artifact rows, trajectory replay rows, proof-critical panel attributes, trace links, and verified badge integration out of `extension.js`.
- Added focused parity-plus panel tests for run-brain artifact fallback/rows, trajectory replay fallback/rows, proof panel data-testids, brain/replay status attributes, side-effect counts, trace links, and badge propagation.
- Extended `parity-plus-panels.js` to own Stage 2/Stage 5 proof text checks for contract readiness parsing and product-lane leak detection, removing those proof helpers from `extension.js`.
- Added focused parity-plus tests for contract flag extraction and raw receipt/trace/path/tool leakage guards.
- Moved Studio Stage 5 stop/cancel/recover lifecycle orchestration out of `extension.js` behind the existing compatibility wrapper while preserving runtime turn submission, stop/resume control projection, clean final-answer checks, and the `studio.stage5StopCancelRecover.exercised` bridge proof envelope.
- Added focused parity-plus tests for Stage 5 stop/cancel/recover submission options, stop/resume projection flags, assistant turn projection, clean answer preview, and bridge proof emission.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/stage7-delegation-lifecycle.js`.
- Moved Studio Stage 7 delegation lifecycle orchestration out of `extension.js` behind the existing compatibility wrapper while preserving daemon parent-thread creation, delegated worker spawn, failed-child persistence/recovery, browser subagent artifact projection, worker/replay panel projection, and the `studio.stage7DelegationLifecycle.exercised` bridge proof envelope.
- Added focused Stage 7 lifecycle tests for parent/child request sequencing, failed-child recovery projection, worker/browser cards, replay rows, receipt propagation, and bridge proof emission.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-cockpit-lifecycle.js`.
- Moved Studio runtime cockpit projection out of `extension.js` behind the existing `projectStudioRuntimeCockpit` wrapper while preserving model-stream proof projection, policy lease denial, sandbox diagnostics, dry-run patch preview/approval, browser discovery, worker/subagent status, replay refresh, and achieved/incomplete timeline behavior.
- Added focused runtime-cockpit lifecycle tests for daemon proof lanes, hunk approval projection, browser/worker cards, replay refresh, achieved timeline emission, and the no-thread blocked path.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/thread-events.js`.
- Moved Studio daemon thread event collection, runtime-event de-duping, max-seq calculation, SSE event fetch, turn fetch, and turn-scoped event expansion out of `extension.js` behind compatibility wrappers.
- Added focused thread-event tests for response alias collection, event identity de-duping, terminal SSE stop behavior, turn-scoped expansion, and product-safe fetch failure handling.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/thread-lifecycle.js`.
- Moved Studio daemon thread lifecycle helpers out of `extension.js` behind compatibility wrappers: Agent/Ask mode profile switching, run-result fallback text, daemon thread creation/projection, and permission-mode updates.
- Added focused thread-lifecycle tests for incompatible-thread reset behavior, thread creation request envelope/projection, route receipt propagation, permission-mode update payload/error reporting, and assistant-result fallback text.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-controls.js`.
- Moved Studio stop/resume runtime controls out of `extension.js` behind compatibility wrappers while preserving daemon interrupt/resume routes, runtime cockpit stop/resume flags, bridge `chat.stop`/`chat.resume` envelopes, timeline entries, and panel refresh behavior.
- Added focused runtime-control tests for stop/resume daemon payloads, bridge context snapshots, cockpit recompute flags, receipt propagation, route-failure logging, and refresh behavior.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/hunk-lifecycle.js`.
- Moved Studio inline diff hunk decision and native hunk navigation lifecycle out of `extension.js` behind compatibility wrappers while preserving workspace-change lifecycle tools, approval decision route, bridge `chat.hunkDecision` envelope, receipt projection, cockpit flags, native compare-editor commands, and refresh behavior.
- Added focused hunk-lifecycle tests for workspace-change accept, approval fallback rejection, blocked decision refresh, and native navigation command/error handling.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/shell-header.js`.
- Moved Autopilot workbench shell-header styles, posture tone mapping, native-shell gating, runtime posture chips, and mode switch action rendering out of `extension.js` while preserving existing call-site names and data-testids.
- Added focused shell-header tests for tone mapping, native shell gating, sanitized posture rendering, command affordances, and product shell selectors.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/mode-body-renderers.js`.
- Moved artifact, policy, connector, and transient activity body renderers out of `extension.js` while preserving command ids, payload affordances, empty-state copy, and product escaping.
- Added focused mode-body renderer tests for artifact actions, policy metrics, connector actions, direct-mode activity affordances, and escaping.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/model-snapshot.js`.
- Moved product model snapshot normalization and compact byte formatting out of `extension.js` while preserving existing model surface and shell-header dependency injection.
- Added focused model-snapshot tests for byte labels, malformed collection fallback, generated-at precedence, and empty-state defaults.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/mode-controller.js`.
- Moved Autopilot mode id lookup, current/previous mode tracking, VS Code context updates, and menu-bar chrome updates out of `extension.js` behind the existing `enterAutopilotMode()` compatibility wrapper.
- Added focused mode-controller tests for view-id mapping, code-mode return target tracking, VS Code context/menu updates, and failed menu-update reporting.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/code-mode-panel.js`.
- Moved the Code mode repository-gate projection, repository row rendering, SVG affordances, CSP nonce wiring, and full Code mode panel HTML out of `extension.js` while preserving existing command ids and product data-testids.
- Added focused code-mode panel tests for current-workspace projection, escaping, command affordances, data-testids, CSP nonce handling, and empty repository fallbacks.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/overview-panel.js`.
- Moved Autopilot Overview panel HTML, overview status projection, command affordance layout, CSP nonce usage, and daemon-owned console copy out of `extension.js`; `extension.js` retains only nonce lifecycle and panel wiring.
- Added focused overview-panel tests for nonce wiring, daemon-owned attributes, command/data-payload affordances, workspace/item escaping, disconnected daemon fallback, connector readiness, receipt posture, and policy issue projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/workflow-composer-panel.js`.
- Moved Workflow Composer webview HTML, workflow asset URI construction, composer CSP, daemon initial-state serialization, and shell-header embedding out of `extension.js`; `extension.js` retains only panel lifecycle and message handling.
- Added focused workflow-composer panel tests for asset URI construction, nonce/CSP handling, daemon connect-source escaping, shell-header preservation, daemon-owned initial state, and `<` escaping inside serialized bootstrap state.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/workflow-composer-panel-lifecycle.js`.
- Moved Workflow Composer panel creation/reuse/disposal, webview message routing, visibility projection, and scenario/capture postMessage scheduling out of `extension.js`.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/studio-panel-lifecycle.js`.
- Moved Agent Studio webview panel creation/reuse/disposal and webview message routing out of `extension.js` while preserving existing local Studio projection state and public bridge request envelopes.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/overview-panel-lifecycle.js`.
- Moved Autopilot Overview panel creation/reuse/disposal and webview bridge/command message routing out of `extension.js`; reordered panel lifecycle composition so shared workbench visibility helpers are initialized before panel managers, and promoted the local `uniqueStrings` helper to avoid composition-time dependency cycles.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/native.js`.
- Moved native command registration composition out of `extension.js` while preserving public command ids, bridge envelopes, mode navigation callbacks, test-hook registration, model daemon action wiring, and the final runtime bridge registration notice.
- Added focused native command registrar tests for command-group ordering, shared dependency wiring, status callbacks, mode navigation, model daemon actions, and `pickString` compatibility behavior.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/prompt-policy.js`.
- Moved Studio prompt/model policy helpers for whitespace compaction, auto-model selector detection, local-workspace prompt detection, harness-probe exclusion, retrieval routing, and workspace-context routing out of `extension.js`.
- Added focused prompt-policy tests for whitespace/model selector normalization, workspace-vs-external retrieval decisions, Ask/Agent workspace context gating, and internal harness probe suppression.
- Extended `prompt-policy.js` to own workspace-target extraction for fallback intent frames, removing the remaining prompt-target helper from `extension.js` and covering explicit path de-duping plus fallback search targets.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-event-selectors.js`.
- Moved pure Studio runtime-event selector helpers for tool matching, completed-tool matching, tool-event counts, turn-id extraction, and turn-scoped event filtering out of `extension.js`.
- Added focused runtime-event selector tests for case-insensitive tool matching, completed-tool detection, count behavior, turn-id aliases, turn filtering, and fallback semantics.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/turn-policy.js`.
- Moved Studio turn policy/product-copy helpers for retrieval fail-closed messaging, retrieval-grounded result detection, Agent max-step selection, approval-pause detection/copy/error construction, and policy-blocked file-read messaging out of `extension.js`.
- Added focused turn-policy tests for retrieval/workspace max-step selection, source-retrieval copy, approval-pause copy/error metadata, and policy-blocked file-read redaction.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-turn-recovery.js` to own prompt extraction, started-time normalization, submitted-turn matching, and terminal-turn classification helpers used by daemon turn recovery.
- Added focused agent-turn-recovery tests for prompt-source precedence, timestamp aliases, submitted prompt/time matching, and terminal projection classification.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/receipt-refs.js`.
- Moved Studio receipt-reference normalization out of `extension.js` while preserving snake/camel aliases, nested event/result/payload summary aliases, object receipt ids, and de-duplication semantics.
- Moved Studio receipt timeline projection and append/de-duplication into the same receipt module while preserving fallback kind/summary copy and injected projection state mutation.
- Added focused receipt-ref tests for alias coverage, nested receipt extraction, de-duplication, missing-record tolerance, receipt projection, and timeline append behavior.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-workspace-changes.js`.
- Moved Studio workspace-change review inspection projection and daemon refresh routing out of `extension.js` while preserving hunk alias normalization, route/query envelope, cockpit markers, and fail-closed logging.
- Added focused workspace-change projection tests for hunk normalization, daemon route/query shape, and daemon-refresh failure tolerance.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-parity-plus-events.js`.
- Moved parity-plus runtime event payload aliasing and panel routing out of `extension.js` while preserving session-brain, trajectory-replay, safety, import-only, and reconnect projection semantics.
- Added focused parity-plus event projection tests for payload aliases, session-brain rows/receipts, trajectory replay, import-only panels, safety panels, and unknown-event fallback.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/tool-response-projection.js`.
- Moved Studio tool-response JSON preview and command-output projection helpers out of `extension.js` while preserving nested result aliases, failed exit-code fallback, and receipt propagation.
- Added focused tool-response projection tests for bounded previews, top-level command aliases, nested diagnostics output, failed fallback exit code, and receipt propagation.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-runtime-events.js`.
- Moved Studio timeline append, runtime-event normalization, response receipt projection, and runtime-cockpit achieved gate recomputation out of `extension.js` while preserving visibility classification and receipt timeline behavior.
- Added focused runtime-event projection tests for timeline metadata, runtime event alias normalization, receipt projection, non-object tolerance, and cockpit achieved gate semantics.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-rail-rows.js`.
- Moved simple Studio runtime rail renderers for timeline, receipts, history, approvals, terminal, replay, and parity-plus panels out of `extension.js` while preserving fallback rows, escaping, and recent-item bounds.
- Added focused runtime-rail row tests for safe escaping, fallback receipt/replay rows, parity delegation, and recent receipt slicing.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/work-run-rows.js`.
- Moved assistant work-run status bar renderers for command labels, sanitized work-summary rows, command-output details, and diff-hunk controls out of `extension.js` while preserving public data-testids and approval/hunk command payloads.
- Added focused work-run row tests for command surface/action labels, sanitized work summaries, settled command-output rows, and hunk control affordances.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/pending-view.js`.
- Moved Studio pending chat placeholder/worklog rendering out of `extension.js` while preserving elapsed command labels, source-chip rendering, command-output excerpts, and hidden non-pending state.
- Added focused pending-view tests for hidden state, command pending rows, public detail/excerpt rendering, source-chip escaping, and non-command paragraph excerpts.
- Removed an unused local `studioIcon` helper from `extension.js`; no call sites or static coverage referenced it.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-cockpit-rows.js`.
- Moved Studio runtime cockpit row renderers for diff review, tool proposals, policy leases, command output, diagnostics, browser/worker status, and compact actionable prompts out of `extension.js` while preserving data-testids, hunk payload attributes, lease flags, and recent row bounds.
- Moved runtime-cockpit patch target extraction and daemon tool-response patch preview hunk construction out of `extension.js` into `runtime-cockpit-rows.js`.
- Added focused runtime-cockpit row tests for diff controls, policy prompts, command/diagnostics cards, browser/worker cards, and action-card receipts.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/turn-rows.js`.
- Moved Studio chat turn row rendering out of `extension.js` while preserving user/latest turn selectors, documented-work rows, artifact/session delegation, assistant answer cards, and product escaping.
- Added focused turn-row tests for stable user/latest selectors, assistant answer cards, documented-work rendering, session/artifact delegation, and unsafe role/content escaping.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/studio/native-diff-preview.js`.
- Moved Studio native diff provider registration, preview document storage, and VS Code diff opening out of `extension.js` while preserving sanitized preview URIs, inline-diff observation projection, and blocked-diff timeline/output behavior.
- Added focused native-diff preview tests for provider content lookup, sanitized URI construction, command invocation, projection mutation, and failure reporting.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/policy-lease-lifecycle.js`.
- Moved the simple request-and-deny policy lease helper behind the policy lease lifecycle module while preserving the existing `extension.js` compatibility wrapper, daemon approval/decision envelopes, projection flags, receipt projection, timeline copy, and output copy.
- Added focused policy-lease lifecycle tests for request-and-deny route shaping, token usage, approval turn payload propagation, projection mutation, receipt projection, timeline output, and deny copy.
- Moved the allow/revoke/expiry live policy-lease exercise behind the same policy lease lifecycle module while preserving the `extension.js` compatibility wrapper, daemon tool/approval/revoke envelopes, dry-run mutation guard, cockpit projection flags, receipt projection, and fixture cleanup.
- Extended focused policy-lease lifecycle tests for the full allow/revoke/expiry exercise request sequence, cockpit projection mutation, receipts, and cleanup behavior.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/durability-panels.js`.
- Moved Studio session-brain lifecycle orchestration out of `extension.js` behind the existing compatibility wrapper while preserving daemon thread/memory/policy envelopes, replay-step projection, runtime-cockpit flags, bridge proof envelope, and product-safe run-brain artifact checks.
- Added focused durability-panel tests for session-brain lifecycle daemon envelope shaping, memory write/policy routing, read-only late-write handling, replay-step projection, runtime-cockpit flags, and bridge proof emission.
- Moved Studio trajectory-replay reconnect orchestration out of `extension.js` behind the existing compatibility wrapper while preserving daemon thread/memory envelopes, side-effect key semantics, reconnect banner projection, replay-step projection, runtime-cockpit flags, and bridge proof envelope.
- Added focused durability-panel tests for trajectory-replay lifecycle daemon envelope shaping, one side-effect write, replay cursor projection, runtime-cockpit flags, and bridge proof emission.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/parity-plus-panels.js`.
- Moved Studio Stage 2 web-repair proof orchestration out of `extension.js` behind the existing compatibility wrapper while preserving prompt submission shape, daemon event replay, contract false-then-true checks, source projection, product transcript cleanliness, and bridge proof envelope.
- Added focused parity-plus tests for Stage 2 proof submission, source projection, final-contract values, completed web tool checks, clean answer preview, and bridge proof emission.
- Moved Studio Stage 5 stop-hook repair proof orchestration out of `extension.js` behind the existing compatibility wrapper while preserving governed validation prompt shape, failed validation detection, stop-hook blocked reply detection, hunk/edit detection, validation rerun checks, product transcript cleanliness, and bridge proof envelope.
- Added focused parity-plus tests for Stage 5 repair-loop submission, failing/passing validation detection, stop-hook block detection, edit/hunk projection, clean answer preview, and bridge proof emission.
- Extended `apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js`.
- Moved Studio projection lifecycle helpers for daemon-thread reset, new-session projection, work cursor capture, and documented-work summary delegation out of `extension.js` while preserving existing call-site names and session preference carry-forward semantics.
- Added focused projection-state lifecycle tests for daemon-thread field reset, answer-stream reset delegation, model/mode/approval preference preservation across new sessions, and work-cursor count projection.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/commands/model-daemon-actions.js`.
- Moved daemon model workbench/catalog action helpers and payload string alias handling out of `extension.js` into the model command adapter boundary while preserving model command route paths, daemon-owned envelopes, download policy gating, and endpoint fail-closed behavior.
- Added focused model-daemon action tests for estimate/load/unload route shaping, catalog search/provider/download payloads, source-url validation, and missing daemon endpoint handling.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/panel-lifecycle.js`.
- Moved workbench panel lifecycle helpers for activity sidebar closing, mode visibility bridge projection, webview view provider rendering/message forwarding, appearance sync, and bridge-state polling out of `extension.js` while preserving daemon-owned bridge envelopes, auto-open timing, and command dispatch behavior.
- Added focused panel-lifecycle tests for visibility projection throttling, listener disposal, theme update de-duping, bridge polling disposal, webview message forwarding, and primary-surface auto-open.
- Added `apps/autopilot/openvscode-extension/ioi-workbench/workbench/persistent-mode-panels.js`.
- Moved Autopilot Models and generic persistent mode panel lifecycle/render refresh logic out of `extension.js` while preserving model proof bridge envelopes, command dispatch, phase capture messages, generic mode disposal cleanup, and code-mode renderer delegation.
- Added focused persistent-mode panel tests for model panel bridge/proof/command forwarding, phase capture scheduling, generic panel refresh/disposal, code-mode delegation, and unknown-mode fail-closed behavior.
- Kept compatibility wrappers in `extension.js` where existing tests or local call sites expect the old function names.
- Fixed live activation-order regressions in `extension.js` by passing lazy dependency wrappers into early Studio composition factories for product-text sanitization, native diff preview, patch-preview hunk projection, and cockpit patch-target extraction; the initial Stage 8 live proof exposed temporal-dead-zone failures for those const destructures, and the final Stage 8/Stage 9 live proofs passed after the wrappers.

Status: `extension.js` is still a composition-heavy file and remains larger than the guide's ideal target. The safe next extractions are Studio projection events, remaining test hooks, panel lifecycle, and command grouping by Studio/workflows/models/runs.

### Runtime Daemon

- Added `packages/runtime-daemon/src/runtime-request-metadata.mjs`.
- Moved request base URL, runtime event cursor parsing, usage request metadata projection, and usage metadata application out of `index.mjs`.
- Passed `RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION` into the helper explicitly so the module stays decoupled from the daemon constants bundle.
- Added `packages/runtime-daemon/src/runtime-doctor-report.mjs`.
- Moved runtime doctor/readiness report projection out of `index.mjs` behind the existing `doctorReport()` compatibility method while preserving required and optional check semantics, doctor-safe endpoint redaction, provider-key reporting, model/MCP/memory projections, and workflow readiness fields.
- Added focused runtime-doctor-report tests for ready/degraded redacted reports and blocked required path failures.
- Added `packages/runtime-daemon/src/threads/thread-runtime-controls.mjs`.
- Moved thread mode/approval normalization, initial and normalized runtime controls, request control injection, model-control update shaping, model policy/workflow context projection, reasoning-effort normalization, and model route receipt binding out of `index.mjs`.
- Added `packages/runtime-daemon/src/threads/model-route-selection.mjs`.
- Moved daemon model route resolution, run route reuse, and local-first fallback selection out of `index.mjs` behind compatibility wrappers while preserving model policy/workflow context shaping, route-selection receipts, fallback evidence refs, and candidate evidence merging.
- Added focused model-route-selection tests for explicit workflow route selection, fallback route/evidence merging, and persisted run route reuse.
- Added `packages/runtime-daemon/src/threads/run-memory-resolution.mjs`.
- Moved run memory injection/write policy orchestration and subagent memory inheritance projection out of `index.mjs` behind compatibility wrappers while preserving chat memory commands, API remember writes, policy block reasons, inherited record filters, effective subagent policy projection, and evidence refs.
- Added focused run-memory-resolution tests for record injection, remember writes, disabled-memory blocking, and subagent inheritance projection.
- Added `packages/runtime-daemon/src/threads/thread-turn-projection.mjs`.
- Moved public thread and turn projection out of `index.mjs` behind existing `threadForAgent()` and `turnForRun()` compatibility methods while preserving schema versions, runtime usage aliases, latest/interrupted status projection, event item ids, memory refs, model route fields, and fixture profiles.
- Added focused thread-turn-projection tests for latest thread projection and closed/open turn projection behavior.
- Added `packages/runtime-daemon/src/threads/context-budget-policy.mjs`.
- Moved context-budget telemetry selection, threshold normalization, context-budget evaluation, coding-tool budget policy shaping, and compaction-policy decisions out of `index.mjs`.
- Added `packages/runtime-daemon/src/repository-context.mjs`.
- Moved read-only repository context projection, branch policy projection, GitHub remote context projection, workspace-trust warning projection, git porcelain counting, and remote credential redaction helpers out of `index.mjs`.
- Added focused repository-context tests for porcelain counting, GitHub remote redaction/metadata, read-only branch/GitHub policy projection, and UI trust override ignoring.
- Added `packages/runtime-daemon/src/http/public-runtime-routes.mjs`.
- Moved the public daemon HTTP request dispatcher, CORS preflight handling, top-level route table, delegated thread/agent/run route dispatch, MCP serve thread requirement, and public route error boundary out of `index.mjs`.
- Added focused public-runtime route tests for preflight, top-level daemon projection dispatch, delegated thread subroutes, and MCP serve validation.
- Added `packages/runtime-daemon/src/threads/managed-session-state.mjs`.
- Moved runtime-backed managed-session inspection/control bridge behavior out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegator methods.
- Added focused managed-session thread-state tests for fixture fallback snapshots, runtime bridge inspection normalization, control command construction, and missing session-id validation.
- Added `packages/runtime-daemon/src/threads/workspace-change-state.mjs`.
- Moved runtime-backed workspace-change review inspection/control bridge behavior out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegator methods.
- Added focused workspace-change thread-state tests for fixture fallback snapshots, runtime bridge inspection normalization, control command construction, and missing change-id validation.
- Added `packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs`.
- Moved runtime-service thread start orchestration, runtime-service turn submit orchestration, runtime-service control-thread bridge calls, start-result normalization, submit-turn normalization, and live-event normalization out of `index.mjs` behind existing `createRuntimeBridgeThread`, `createRuntimeBridgeTurn`, `resumeThread`, `interruptTurn`, `normalizeRuntimeBridgeThreadStart`, `normalizeRuntimeBridgeTurnSubmit`, and `normalizeRuntimeBridgeLiveEvent` compatibility methods.
- Added focused runtime bridge thread tests for bridge input shaping, updated-agent persistence, event append behavior, bridge-unavailable error mapping, turn submit max-step clamping, in-flight cleanup, run persistence, control-thread input/error handling, event default projection, start-contract failures, submit-turn projection defaults, submit-turn contract failures, and live-event envelope normalization.
- Added `packages/runtime-daemon/src/bridges/runtime-agent-bridge.mjs`.
- Moved runtime bridge capability checks and runtime-service external-blocker shaping out of `index.mjs` behind existing `assertRuntimeBridgeAvailable` and `runtimeBridgeUnavailable` compatibility methods.
- Added `packages/runtime-daemon/src/computer-use-inputs.mjs`.
- Moved computer-use action kind normalization, approval/control input parsing, browser session-mode selection, CDP timeout/endpoint checks, visual GUI observation metadata projection, media-type inference, and controlled-relaunch unavailable execution shaping out of `index.mjs` behind compatibility wrappers.
- Removed the remaining `index.mjs` controlled-relaunch unavailable execution wrapper; the daemon now injects shared evidence-ref de-duplication directly into `computer-use-inputs.mjs`.
- Added `packages/runtime-daemon/src/runtime-mcp-helpers.mjs`.
- Moved MCP server/tool resolution, MCP serve tool descriptor/result shaping, JSON-RPC envelopes, live transport mode metadata, registry enrichment, catalog summary/exposure shaping, mutation-input normalization, config-source filtering, and catalog/tool search limit helpers out of `index.mjs` behind compatibility wrappers.
- Added focused runtime MCP helper tests for server/tool identity resolution, MCP serve descriptor/result metadata, JSON-RPC error mapping, live transport inference, deferred catalog exposure, mutation input normalization, and registry projection counts.
- Added `packages/runtime-daemon/src/skill-hook-catalog.mjs`.
- Moved skill/hook source discovery, SKILL.md metadata parsing, hook definition normalization, redacted command hashing, validation issue projection, and active catalog hashing out of `index.mjs`.
- Added focused skill-hook catalog tests for workspace/global compatibility sources, filesystem discovery, command redaction, validation degradation, metadata parsing, and compatibility alias normalization.
- Added `packages/runtime-daemon/src/skill-hook-manifest.mjs`.
- Moved active skill/hook manifest selection, dry-run policy planning, preview invocation ledger projection, blocked-hook escalation shaping, and hook escalation receipt projection out of `index.mjs`.
- Added focused skill-hook manifest tests for explicit/configured selection normalization, redacted manifest projection, dry-run blocked/would-run decisions, invocation ledger counts, and escalation receipt details.
- Added `packages/runtime-daemon/src/threads/thread-replay.mjs`.
- Moved runtime event append/idempotency, thread-start/run-event projection, cursor bounds, stream lookup, replay-by-stream/turn, persisted event registration, and stream-path helpers out of `index.mjs` behind existing replay compatibility methods.
- Added `packages/runtime-daemon/src/threads/thread-store.mjs`.
- Moved agent list/get/update/delete, thread-to-agent lookup, in-flight runtime turn registration, and thread-turn resolution helpers out of `index.mjs` behind existing store compatibility methods.
- Extended `thread-store.mjs` to own run list/get and run/thread usage projection helpers while preserving existing `AgentgresRuntimeStateStore` method names.
- Added `packages/runtime-daemon/src/threads/thread-persistence.mjs`.
- Moved agent/run record persistence, run projection writes, and persisted run operation terminal-event summarization out of `index.mjs` behind existing `writeAgent` and `writeRun` compatibility methods.
- Extended `packages/runtime-daemon/src/threads/thread-persistence.mjs`.
- Moved subagent record persistence, operation-log append/count behavior, state path construction, and quiet projection deletion out of `index.mjs` behind existing store method names.
- Extended `packages/runtime-daemon/src/threads/thread-persistence.mjs`.
- Moved runtime state directory bootstrap, schema projection, and persisted state loading out of `index.mjs` behind existing `ensureDirs`, `writeSchema`, and `load` store methods.
- Added `packages/runtime-daemon/src/runtime-tool-catalog.mjs`.
- Moved runtime account/node/tool catalog projections, tool governance metadata normalization, and doctor-safe runtime node redaction out of `index.mjs` while preserving existing public methods and MCP serve descriptor behavior.
- Added `packages/runtime-daemon/src/repository-projections.mjs`.
- Moved public repository/GitHub projection wrapper orchestration for repository lists, repository context, branch policy, GitHub context, PR attempts, issue context, review gates, and GitHub PR create plans out of `index.mjs` behind existing store methods.
- Added `packages/runtime-daemon/src/repository-workflow-projections.mjs`.
- Moved concrete GitHub issue-context, PR-attempt, review-gate, PR branch/diff artifact, and GitHub PR create-plan builders out of `index.mjs` behind dependency-injected workflow projection helpers while preserving existing store method behavior.
- Added `packages/runtime-daemon/src/runtime-artifacts.mjs`.
- Moved runtime artifact record construction and run artifact reference resolution out of `index.mjs` while preserving route-handler artifact lookup and runtime-record projection injection.
- Added focused runtime artifact tests for stable artifact ids/content serialization, string content preservation, id/name/ref lookup, `artifact:` prefixed lookup, and missing artifact tolerance.
- Added `packages/runtime-daemon/src/runtime-coding-tool-approval.mjs`.
- Moved coding-tool effect approval classification, workflow approval policy projection, approval manifest creation, and approval retry-manifest matching out of `index.mjs`.
- Added focused coding-tool approval tests for local-read bypass, nested workflow policy controls, manifest schema aliases, ignored UI override detection, omitted no-gate manifests, and snake/camel retry matching.
- Added `packages/runtime-daemon/src/runtime-invocation-results.mjs`.
- Moved coding-tool invocation result projection plus computer-use browser discovery, control, and native-browser multi-event result projection out of `index.mjs`.
- Added focused invocation-result tests for coding-tool replay aliases, browser discovery object normalization, control handoff/cleanup aliases, ordered native-browser event merging, receipt/artifact/rollback de-duping, and projection payload precedence.
- Added `packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.mjs`.
- Moved coding-tool budget recovery action normalization, target-node selection, recovery-policy shaping, retry-limit bounding, budget-blocked event detection, and recovery result envelope projection out of `index.mjs`.
- Added focused coding-tool budget recovery tests for action aliases, invalid action rejection, target-node de-duping, default policy shaping, blocked-event detection, retry-limit bounds, and snake/camel result aliases.
- Added `packages/runtime-daemon/src/runtime-approval-lease.mjs`.
- Moved approval lease metadata construction/recovery, approval lease expiry state derivation, approval decision normalization, and approval decision reason mapping out of `index.mjs`.
- Added focused approval lease tests for TTL expiry calculation, policy hash/default lease ids, nested/top-level payload aliases, decision lease precedence, expired lease detection, approve/reject aliases, and invalid decision errors.
- Added `packages/runtime-daemon/src/diagnostics-repair-execution.mjs`.
- Moved diagnostics repair execution result projection, operator override approval shaping, restore-apply approval/conflict/status/policy-ref helpers, and restore-apply summary text out of `index.mjs` behind dependency-injected helper exports.
- Added focused diagnostics repair execution tests for approval/conflict policy refs and public snake/camel retry and operator-override envelopes.
- Added `packages/runtime-daemon/src/diagnostics-repair-policy.mjs`.
- Moved diagnostics repair policy config normalization, repair context shaping, rollback repair policy decision construction, and diagnostics/restore policy normalization out of `index.mjs` behind dependency-injected helper exports.
- Added focused diagnostics repair policy tests for config aliases, context envelopes, rollback refs, decision defaults, and policy decision refs.
- Added `packages/runtime-daemon/src/diagnostics-feedback.mjs`.
- Moved post-edit diagnostics config shaping, diagnostics feedback compaction, retry feedback, blocking gate construction, prompt injection, and runtime bridge diagnostics event insertion out of `index.mjs` behind dependency-injected helper exports.
- Added focused diagnostics feedback tests for config aliases, compacted context bounds, blocking-gate policy refs, request/prompt injection, repair retry envelopes, and runtime bridge event insertion order.
- Added `packages/runtime-daemon/src/runtime-usage-events.mjs`.
- Moved runtime bridge usage-delta insertion, usage delta payload shaping, context-pressure delta/alert payload shaping, and context pressure rounding/status helpers out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime usage event tests for telemetry aliases, context-pressure alert actions, insertion order after `turn.started`, and public event kinds.
- Added `packages/runtime-daemon/src/runtime-memory-helpers.mjs`.
- Moved runtime memory policy override aliases, memory write approval/blocking, list filter aliases, memory operation vocabulary, and subagent memory inheritance policy/receipt helpers out of `index.mjs` behind dependency-injected helper exports.
- Moved subagent memory receiver selection, inheritance-mode normalization, explicit selector detection, and inheritance gating into `runtime-memory-helpers.mjs`.
- Added focused runtime memory helper tests for policy aliases, write blocking, operation/event vocabulary, subagent inheritance evidence, receiver/selector inheritance behavior, and filter alias normalization.
- Added `packages/runtime-daemon/src/threads/thread-memory-state.mjs`.
- Moved thread/agent memory projection, memory policy/path lookup, memory writes/edits/deletes, policy mutation adapter behavior, memory control event projection, memory status projection, and memory validation out of `index.mjs` behind existing `AgentgresRuntimeStateStore` method names.
- Added `packages/runtime-daemon/src/threads/workspace-trust-state.mjs`.
- Moved workspace trust warning emission and acknowledgement lookup/event projection out of `index.mjs` behind existing `appendWorkspaceTrustWarningEvent` and `acknowledgeWorkspaceTrustWarning` store methods.
- Added `packages/runtime-daemon/src/threads/thread-fork-state.mjs`.
- Moved thread fork idempotency handling, fork-agent creation options, and `thread.forked` event projection out of `index.mjs` behind the existing `forkThread` store method.
- Added `packages/runtime-daemon/src/runtime-run-helpers.mjs`.
- Moved run result text, mode-to-task-family/strategy mapping, capability sequence construction, and run-event id/cursor construction out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime run helper tests for mode vocabulary, memory-specific result text, capability sequence additions, and stable event id/cursor shaping.
- Added `packages/runtime-daemon/src/runtime-run-event-helpers.mjs`.
- Moved run-event status mapping, policy decision ref extraction, string payload record conversion, component/workflow-node mapping, receipt/artifact refs, and computer-use artifact ref extraction out of `index.mjs`.
- Added focused runtime run-event helper tests for status mapping, policy ref de-duping, payload conversion, receipt/artifact refs, workflow nodes, and computer-use artifacts.
- Added `packages/runtime-daemon/src/runtime-run-cancellation.mjs`.
- Moved run cancellation terminal-event continuity, runtime task/job/checklist rewrite, canceled job/run terminal event projection, checklist receipt repair, and runtime-checklist artifact repair out of `index.mjs` behind the existing `cancelRun` store method.
- Added focused runtime run-cancellation tests for terminal replay cleanup, runtime projection updates, missing task/checklist event append behavior, checklist receipt/artifact repair, failure-ontology labeling, and `run.cancel` persistence.
- Added `packages/runtime-daemon/src/runtime-event-envelopes.mjs`.
- Moved runtime bridge computer-use derived-event insertion, derived computer-use event envelope construction, TTI envelope construction, and normalized runtime event envelope projection out of `index.mjs`.
- Added focused runtime event-envelope tests for computer-use derived insertion/de-duping, diagnostics/computer-use TTI envelope schema selection, and normalized replay compatibility fields.
- Added `packages/runtime-daemon/src/runtime-event-payloads.mjs`.
- Moved run-event payload summary projection out of `index.mjs` behind a dependency-injected helper factory.
- Added focused runtime event-payload tests for computer-use, memory, diagnostics, policy gate, repository, runtime task, usage telemetry, context-pressure alert, and model route summaries.
- Added `packages/runtime-daemon/src/runtime-coding-tool-results.mjs`.
- Moved coding-tool public result draft stripping, command-stream request/chunk helpers, coding artifact metadata/read-result projection, and terminal-event counting out of `index.mjs` behind dependency-injected helper exports while preserving existing public artifact schema behavior.
- Added focused runtime coding-tool result tests for draft stripping, artifact metadata/read slicing, command stream chunking, and terminal-event vocabulary injection.
- Added `packages/runtime-daemon/src/runtime-value-helpers.mjs`.
- Moved shared array/string normalization, boolean-option normalization, safe-id hashing, doctor-check shaping, workspace-relative path bounding, operator-control source normalization, and operator-control append behavior out of `index.mjs` behind direct helper exports.
- Added focused runtime value-helper tests for normalization, boolean options, safe ids, hashes, workspace-relative paths, doctor-check envelopes, and operator-control de-duping.
- Added `packages/runtime-daemon/src/runtime-agent-options.mjs`.
- Moved agent option summaries, Cursor compatibility discovery, runtime mode/provider availability checks, memory option merging, and provider-key doctor reporting out of `index.mjs` behind dependency-injected helper exports.
- Added focused runtime agent-options tests for Cursor MCP/hook/skill discovery, option summaries, provider endpoint fail-closed behavior, memory merge precedence, and provider-key doctor redaction.
- Added `packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs`.
- Moved agent creation and canonical run creation orchestration out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore.createAgent()` and `createRun()` delegates, while preserving model-route resolution, runtime-control initialization, MCP registry projection, provider fail-closed checks, memory/run/skill-hook handoff, usage telemetry aliases, trace usage projection, and persistence operations.
- Added focused runtime agent/run lifecycle tests for agent route/control/registry persistence, hosted-provider fail-closed behavior, learn-mode prompt fallback, run memory/skill catalog handoff, approval/thread mode projection, usage telemetry aliases, and run persistence.
- Added `packages/runtime-daemon/src/runtime-repository-surface.mjs`.
- Moved public repository, branch-policy, GitHub context, PR attempt, issue context, review gate, and PR-create-plan surface methods out of `index.mjs` behind `AgentgresRuntimeStateStore` compatibility delegates while preserving read-only projection dependencies and workspace-root scoping.
- Added focused repository-surface tests for projection delegation, workflow projection factory wiring, dependency injection, and store cwd propagation.
- Added `packages/runtime-daemon/src/runtime-tool-surface.mjs`.
- Moved public account, runtime-node, and governed tool-catalog surface methods out of `index.mjs` behind `AgentgresRuntimeStateStore` compatibility delegates while preserving env-backed account/node projection and coding-tool catalog injection.
- Added focused runtime-tool-surface tests for env propagation, node/account delegation, tool options, and coding-contract handoff.
- Added `packages/runtime-daemon/src/runtime-skill-hook-surface.mjs`.
- Moved public skill/hook catalog, skill registry projection, and hook registry projection methods out of `index.mjs` behind `AgentgresRuntimeStateStore` compatibility delegates while preserving workspace/home discovery scoping, redaction, evidence refs, and skill-vs-hook source filtering.
- Added focused runtime-skill-hook-surface tests for catalog delegation, default/explicit cwd handling, skill projection shaping, hook projection shaping, and source filtering.
- Added `packages/runtime-daemon/src/runtime-task-job-surface.mjs`.
- Moved public task/job list, create, get, and cancel methods out of `index.mjs` behind `AgentgresRuntimeStateStore` compatibility delegates while preserving task/job projection helpers, run cancellation mapping, status filtering, existing-agent lookup, and synthesized-agent defaults.
- Added focused runtime-task-job-surface tests for sorted/filtered task and job projection, create-task payload shaping, existing/synthesized agent flows, get-by-public-id/run-id behavior, cancel delegation, and not-found errors.
- Added `packages/runtime-daemon/src/runtime-run-read-surface.mjs`.
- Moved run lookup/listing, run/thread/list usage projection, authority evidence summary, legacy event replay, canonical replay, trace projection, and canonical state path projection out of `index.mjs` behind compatibility delegates while leaving state-mutating context-budget and compaction policy evaluators local for a later policy slice.
- Added focused runtime-run-read-surface tests for get/list delegation, run/thread/list usage shaping, authority evidence side effects, legacy replay cursor behavior, trace projection, canonical replay, and canonical path projection.
- Added `packages/runtime-daemon/src/runtime-context-policy-surface.mjs`.
- Moved state-mutating context-budget and compaction-policy evaluation out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore.evaluateContextBudget()` and `evaluateCompactionPolicy()` delegates while preserving route-handler method names, event envelopes, schema versions, idempotency keys, compaction execution, and thread/run usage fallback behavior.
- Added focused runtime-context-policy-surface tests for run-scoped budget event projection, workflow-only budget evaluation, compact execution artifact linking, required-thread errors, and approval-required compaction status.
- Extended `packages/runtime-daemon/src/runtime-context-policy-surface.mjs` to own direct thread compaction behind the existing `AgentgresRuntimeStateStore.compactThread()` compatibility delegate while preserving public route method names, context-compaction envelopes, idempotency keys, receipt/policy refs, run operator controls, run context-compaction trace, and runless agent writeback.
- Extended focused runtime-context-policy-surface tests for direct compaction run writeback and runless thread/agent writeback.
- Added `packages/runtime-daemon/src/runtime-identifiers.mjs`.
- Moved runtime thread/agent/run/turn/session id derivation, runtime-backed agent detection, fixture profile defaults, and lifecycle/thread status normalization out of `index.mjs`.
- Added focused runtime identifier tests for prefix compatibility, event stream ids, runtime session fallback, fixture profile override/null preservation, runtime profile detection, and lifecycle status aliases.
- Added `packages/runtime-daemon/src/runtime-thread-event-surface.mjs`.
- Moved public thread turn listing/get, thread/run event replay queries, thread-start/run projection triggers, runtime-event append/replay cursor helpers, event-stream registration/path helpers, and thread/turn projection delegates out of `index.mjs` behind compatibility-preserving store methods.
- Added focused runtime-thread-event-surface tests for turn listing/get errors, thread/run replay routing, helper dependency injection, projection delegation, event-stream paths, cursor assertions, and thread/turn projection delegation.
- Added `packages/runtime-daemon/src/runtime-conversation-artifact-surface.mjs`.
- Moved public conversation artifact create/list/get/revisions/action/export/promote methods out of `index.mjs` behind compatibility-preserving store delegates while keeping artifact not-found behavior and thread-id payload shaping stable.
- Added focused runtime-conversation-artifact-surface tests for artifact create/list/get/revisions delegation, action/export/promote delegation, and not-found preservation.
- Added `packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs`.
- Moved public MCP server/tool/resource/prompt list, MCP tool search/fetch, MCP manager status, MCP validation, and active-context server composition out of `index.mjs` behind compatibility-preserving store delegates while keeping workspace/agent/model-mounting source merging, server filtering, route metadata, counts, validation envelopes, and fetch not-found behavior stable.
- Added focused runtime-mcp-catalog-surface tests for context server de-duplication, thread/workspace source filtering, model-mounting catalog normalization, tool/resource/prompt projections, global/thread tool search, exact tool fetch, fetch not-found behavior, status counts/routes, and validation envelopes.
- Added `packages/runtime-daemon/src/runtime-mcp-control-surface.mjs`.
- Moved MCP registry import/add/remove mutation handling, live status discovery, enable/disable controls, manager tool invocation, status/validation control events, and MCP control-event envelope construction out of `index.mjs` behind compatibility-preserving store delegates while keeping thread route method names and public control payload shapes stable.
- Added focused runtime-mcp-control-surface tests for required-thread errors, add/remove mutation envelopes, blocked mutation validation, enable/status/validation control events, simulated invocation success, approval-required invocation blocking, receipt refs, and policy decision refs.
- Added `packages/runtime-daemon/src/runtime-mcp-serve-surface.mjs`.
- Moved MCP serve status projection, allowed coding-tool catalog projection, JSON-RPC lifecycle handling, batch notification filtering, and governed `tools/call` invocation shaping out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while keeping the public `/v1/mcp/serve` and `/v1/threads/{thread_id}/mcp/serve` route-facing methods stable.
- Added focused runtime-mcp-serve-surface tests for status/catalog projection, initialize/ping/list lifecycle methods, initialized notification filtering, malformed/disallowed/unsupported errors, and `tools/call` workflow graph/node/input shaping.
- Added `packages/runtime-daemon/src/runtime-thread-control-surface.mjs`.
- Moved thread mode/model/thinking update orchestration, thread control event envelope shaping, control receipt/policy refs, model-route control persistence, and workspace trust warning/acknowledgement delegation out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates.
- Added focused runtime-thread-control-surface tests for mode update envelopes with workspace-trust warnings, model/thinking route-control persistence, and workspace-trust acknowledgement delegation.
- Added `packages/runtime-daemon/src/runtime-subagent-surface.mjs`.
- Moved subagent list/get/projection helpers and daemon-owned subagent control event-envelope shaping out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates. This creates the ownership seam for later spawn/wait/input/cancel/resume/assign migration without changing route-facing method names.
- Added focused runtime-subagent-surface tests for role-filtered list projection, subagent lookup/not-found preservation, and subagent control event receipt/policy envelope shaping.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent spawn orchestration behind the existing `AgentgresRuntimeStateStore.spawnSubagent()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for spawn metadata, context pressure/source refs, prompt validation, role concurrency policy blocking, blocked-budget policy persistence, spawn event envelopes, and spawn evidence refs.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent wait and result-read orchestration behind existing `AgentgresRuntimeStateStore.waitSubagent()` and `getSubagentResult()` compatibility delegates.
- Extended focused runtime-subagent-surface tests for wait persistence/result envelopes and output-contract result projection.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent assignment orchestration behind the existing `AgentgresRuntimeStateStore.assignSubagent()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for role/tool/model/merge/cancellation metadata updates, assignment history persistence, assignment event envelopes, and assignment evidence refs.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent cancellation orchestration behind the existing `AgentgresRuntimeStateStore.cancelSubagent()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for inherited cancellation metadata, canceled run receipt preservation, cancellation event envelopes, persistence, and cancellation evidence refs.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own parent-child cancellation propagation behind the existing `AgentgresRuntimeStateStore.propagateSubagentCancellation()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for propagated cancellation request shaping, inherited cancellation metadata, detached-child skip reporting, already-canceled skip reporting, propagation counts, event refs, and receipt aggregation.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent input orchestration behind the existing `AgentgresRuntimeStateStore.sendSubagentInput()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for input history persistence, previous-run linkage, input event envelopes, input validation, canceled-subagent policy blocking, result projection, and evidence refs.
- Extended `packages/runtime-daemon/src/runtime-subagent-surface.mjs` to own subagent resume/restart orchestration behind the existing `AgentgresRuntimeStateStore.resumeSubagent()` compatibility delegate.
- Extended focused runtime-subagent-surface tests for resume history persistence, restart metadata, cancellation clearing/history retention, resume event envelopes, blocked-budget policy persistence, and resume evidence refs.
- Added `packages/runtime-daemon/src/runtime-approval-surface.mjs`.
- Moved approval request, approval decision, approval revocation, latest approval request lookup, and latest approval decision lookup out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving route-facing event envelopes, approval lease metadata, receipt/policy refs, run/thread projection responses, and run/agent persistence updates.
- Added focused runtime-approval-surface tests for approval request blocking, approval decision lease activation, approval revocation with prior-decision linkage, latest-event lookup, and fail-closed missing id/request behavior.
- Added `packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.mjs`.
- Moved coding-tool budget blocked-event lookup and recovery request/approval/retry orchestration out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore.latestCodingToolBudgetBlockedEventForRun()` and `codingToolBudgetRecoveryForRun()` delegates while preserving approval manifests, retry-limit semantics, route-facing result aliases, receipt/policy refs, runtime event envelopes, and run operator-control writeback.
- Added focused runtime-coding-tool-budget-recovery-surface tests for blocked-event lookup, approval request manifests, missing approval/decision gating, rejected decisions, approved retry writeback, retry-limit enforcement, and thread/run compatibility boundaries.
- Added `packages/runtime-daemon/src/runtime-workflow-edit-surface.mjs`.
- Moved workflow edit proposal, proposal lookup, apply lookup, approval-satisfaction, and approved apply orchestration out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving proposal/apply event envelopes, approval manifests, result aliases, receipt/policy refs, workspace-boundary enforcement, mutation gating, and idempotent apply replay.
- Added focused runtime-workflow-edit-surface tests for proposal manifest aliases, approval request wiring, blocked apply before decision, approved file-write apply, idempotent replay, workspace escape rejection, required proposal ids, and missing proposal errors.
- Added `packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs`.
- Moved coding-tool approval satisfaction, approval-required blocked result shaping, and budget-blocked event/result shaping out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving approval lease expiry handling, manifest matching, approval request envelopes, budget policy events, receipt/policy refs, rollback refs, diagnostics repair context aliases, and result schema aliases.
- Added focused runtime-coding-tool-governance-surface tests for approval states, rejected/expired decisions, approval-required result envelopes, and budget-block event envelopes.
- Added `packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.mjs`.
- Moved coding-tool artifact draft materialization, artifact read policy, tool-result retrieval, command-stream event shaping, and visual GUI observation artifact materialization out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving artifact schema aliases, persisted artifact records, artifact read chunking, cross-thread read blocking, retrieve-result target validation, channel fallback ordering, shell fallback aliases, command-stream idempotency keys, stream sequencing, final control events, visual artifact base64 encoding, source-path redaction, media-type inference, size/unreadable fail-closed envelopes, receipt refs, and artifact refs.
- Added focused runtime-coding-tool-artifact-surface tests for draft materialization/writeback, owned-thread reads, cross-thread policy blocking, retrieve-result by channel/artifact id, required retrieve targets, command-stream event envelopes, skipped non-stream requests, visual GUI artifact materialization, explicit-ref skips, unreadable visual artifacts, and visual artifact size limits.
- Added `packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs`.
- Moved workspace snapshot preparation, snapshot content artifact materialization, snapshot event/list projection, workspace snapshot content-package lookup, restore preview/apply orchestration, restore preview/apply artifact materialization, and restore preview/apply event shaping out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving snapshot ids/hashes, content capture redaction, restore support flags, route-facing schema aliases, content-package fail-closed errors, restore artifact records, restore idempotency keys, restore preview/apply status/count aliases, approval/conflict policy refs, receipt refs, artifact refs, and rollback refs.
- Added focused runtime-workspace-snapshot-surface tests for patch snapshot preparation, persisted content artifacts, snapshot event/list envelopes, content-package lookup and unavailable errors, restore preview/apply artifact materialization, restore preview/apply event envelopes, and real temp-workspace restore preview/apply behavior.
- Added `packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.mjs`.
- Moved post-edit diagnostics invocation and pending diagnostics feedback packaging out of `index.mjs` behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving diagnostics mode gating, changed-file filtering, LSP diagnostics tool request envelopes, rollback refs, diagnostics repair context aliases, repair policy config propagation, last-injected sequence filtering, and compact diagnostics feedback handoff.
- Added focused runtime-diagnostics-feedback-surface tests for skipped/pathless post-edit diagnostics, LSP diagnostics invocation envelopes, repair context projection, pending diagnostics filtering after the last injected event, and skip-mode feedback suppression.
- Added `packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs`.
- Moved diagnostics repair decision execution routing out of `index.mjs` behind the compatibility-preserving `AgentgresRuntimeStateStore.executeDiagnosticsRepairDecision()` delegate while preserving decision validation, action allow-listing, availability checks, snapshot-ref resolution, repair retry/operator override/restore preview/restore apply dispatch, restore approval idempotency keys, restore conflict policy aliases, execution event append calls, result aliases, receipt refs, artifact refs, policy refs, and rollback refs.
- Added focused runtime-diagnostics-repair-surface tests for restore-apply request aliases, retry/override/preview dispatch, missing target, unsupported action, unavailable decision, and missing snapshot failures.
- Extended `packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs` to own diagnostics operator override execution, operator override event construction, repair retry turn creation, repair retry event construction, repair decision lookup, and final repair decision executed-event construction behind compatibility-preserving `AgentgresRuntimeStateStore` delegates while preserving idempotency keys, target turn/run lookup, blocked/completed override behavior, run writeback, injected retry diagnostics feedback, gate filtering, action aliases, receipt refs, artifact refs, policy refs, rollback refs, and public result aliases.
- Added focused runtime-diagnostics-repair-surface tests for completed operator override writeback, repair retry run creation and event projection, latest matching gate resolution, and final execution-event aliases.
- Added `packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs`.
- Moved `AgentgresRuntimeStateStore.invokeThreadTool()` coding-tool orchestration out of `index.mjs` behind a compatibility-preserving delegate while preserving computer-use sync dispatch, not-found handling, coding-tool input shaping, idempotency replay, receipt ids, diagnostics repair context aliases, budget blocked policy errors, approval blocking, tool execution callbacks, artifact draft materialization, apply-patch workspace snapshots, command-stream events, runtime event envelopes, post-edit diagnostics, workspace snapshot events, and public result aliases.
- Added focused runtime-coding-tool-invocation-surface tests for completed apply-patch invocation, duplicate idempotent replay, budget blocks, approval blocks, computer-use dispatch, and not-found behavior.
- Replaced leftover `computer-use-inputs` pass-through wrappers in `index.mjs` with direct named imports, keeping the controlled-relaunch unavailable wrapper only where `index.mjs` injects canonical `uniqueStrings`.
- Replaced leftover `runtime-mcp-helpers` pass-through wrappers in `index.mjs` with direct named imports, keeping MCP implementation ownership in `runtime-mcp-helpers.mjs`.

Status: `index.mjs` still owns the large state store and public route composition. Safe next extractions are daemon service lifecycle, remaining thread store persistence, and route registration glue. Subagent lifecycle orchestration, including parent-child cancellation propagation, now lives behind `runtime-subagent-surface.mjs` compatibility delegates; approval control orchestration now lives behind `runtime-approval-surface.mjs`; coding-tool budget recovery orchestration now lives behind `runtime-coding-tool-budget-recovery-surface.mjs`; workflow-edit proposal/apply orchestration now lives behind `runtime-workflow-edit-surface.mjs`; coding-tool approval/budget governance shaping now lives behind `runtime-coding-tool-governance-surface.mjs`; coding-tool artifact/readback/command-stream/visual-artifact behavior now lives behind `runtime-coding-tool-artifact-surface.mjs`; coding-tool invocation orchestration now lives behind `runtime-coding-tool-invocation-surface.mjs`; workspace snapshot/restore behavior now lives behind `runtime-workspace-snapshot-surface.mjs`; post-edit diagnostics feedback behavior now lives behind `runtime-diagnostics-feedback-surface.mjs`; and diagnostics repair decision dispatch plus override/retry/event helper behavior now lives behind `runtime-diagnostics-repair-surface.mjs`.

### Model Mounting

- Added `packages/runtime-daemon/src/model-mounting/environment.mjs`.
- Moved LM Studio discovery gates, internal fixture exposure gates, live catalog/download gates, and catalog/download timeout parsing out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-registry.mjs`.
- Moved catalog provider port ordering and provider status projection out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-entries.mjs`.
- Moved fixture catalog records, local manifest payload normalization, Hugging Face catalog entry shaping, Ollama artifact catalog entry shaping, variant projection, and catalog entry enrichment out of `model-mounting.mjs`.
- Moved model quantization parsing into `catalog-helpers.mjs` so catalog entries and local artifact metadata share one parser.
- Added `packages/runtime-daemon/src/model-mounting/provider-auth.mjs`.
- Moved provider secret input detection, vault ref sanitization, hosted-provider fail-closed checks, provider auth header normalization, and vault-backed provider header resolution out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs`.
- Moved OAuth vault-ref construction, PKCE challenge generation, authorization URL redaction, token expiry/refresh predicates, public OAuth session/state projection, OAuth boundary projection, and token response validation out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs`.
- Moved configurable catalog provider checks, catalog provider config updates, source material vault binding, catalog auth scheme normalization, catalog auth header resolution, and request-time catalog auth header construction out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-ports.mjs`.
- Moved fixture, local manifest, Ollama, Hugging Face, and custom HTTP catalog provider port construction plus catalog provider health helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/protocol-responses.mjs`.
- Moved OpenAI chat/completions/responses/embeddings and Anthropic message response shaping plus deterministic embedding vector generation out of `model-mounting.mjs`, while preserving compatibility re-exports from `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-protocol.mjs`.
- Moved provider request body shaping, provider output extraction, usage normalization, public trace summarization, deterministic fixture text/token helpers, and safe truncation helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/local-system-probes.mjs`.
- Moved public command execution wrappers, LM Studio CLI parsers/projections, local artifact inspection and metadata parsing, hardware snapshots, file readers, executable discovery, and native-local resource estimates out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs`.
- Moved provider-kind driver mapping, default backend mapping, response-state protocol checks, and deterministic low-variance invocation coalescing helpers out of `model-mounting.mjs`.
- Added `packages/runtime-daemon/src/model-mounting/provider-driver-factory.mjs`.
- Moved concrete provider driver construction out of `model-mounting.mjs` behind the existing `ModelMountingState.driverForProvider()` compatibility method.
- Added focused provider-driver factory tests for concrete driver routing, stateful driver state injection, and explicit driver override behavior.
- Added `packages/runtime-daemon/src/model-mounting/load-policy.mjs`.
- Moved load-policy normalization, load-option normalization, runtime-engine default load options, TTL detection, LM Studio CLI load-argument shaping, and loaded-instance expiry calculation out of `model-mounting.mjs`.
- Added focused load-policy tests for string policies, snake/camel aliases, runtime-engine defaults, explicit TTL detection, expiration semantics, and LM Studio public CLI args.
- Added `packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs`.
- Moved native-local query extraction, deterministic native fixture output, native-local JSONL stream record shaping, JSONL stream construction, and deterministic stream delay handling out of `model-mounting.mjs`.
- Added focused native-local fixture tests for query extraction, deterministic embedding/mode output, stream records, stream abort handling, and bounded stream delay overrides.
- Added `packages/runtime-daemon/src/model-mounting/provider-transport.mjs`.
- Moved provider JSON/stream HTTP transport, provider-open retry operation recording, provider HTTP error shaping, and provider command error shaping out of `model-mounting.mjs`.
- Added focused provider-transport tests for local JSON fetch, tolerated HTTP failures, local-only endpoint rejection, provider error redaction, and command stderr hashing.
- Added `packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs`.
- Moved native-local and deterministic fixture provider driver classes out of `model-mounting.mjs`.
- Added focused provider-local-driver tests for fixture invocation, native-local load lifecycle, native-local JSONL streaming, and stream-abort backend logging.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs`.
- Moved the OpenAI-compatible provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam for hosted-compatible, LM Studio, vLLM, and llama.cpp callers.
- Added focused OpenAI-compatible driver tests for model listing, chat completion invocation, and responses-to-chat fallback.
- Added `packages/runtime-daemon/src/model-mounting/provider-ollama-driver.mjs`.
- Moved the Ollama provider driver out of `model-mounting.mjs` while preserving the same driver dispatch seam.
- Added focused Ollama driver tests for model listing, loaded model projection, chat invocation, embedding invocation, and load/unload probes.
- Added `packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs`.
- Moved the vLLM and llama.cpp provider driver wrappers out of `model-mounting.mjs` while preserving the shared OpenAI-compatible driver composition.
- Added focused backend-driver tests for backend URL promotion, supervised load/unload evidence, and loaded instance projection.
- Added `packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs`.
- Moved the LM Studio public CLI provider driver out of `model-mounting.mjs` while preserving OpenAI-compatible invoke/stream composition.
- Added focused LM Studio driver tests for absent CLI fail-closed behavior and public CLI health/start/stop/load/unload lifecycle commands.
- Added `packages/runtime-daemon/src/model-mounting/wallet-authority.mjs`.
- Moved the Agentgres wallet authority capability grant/authorization/revocation adapter out of `model-mounting.mjs`.
- Added focused wallet authority tests for grant creation, authorization, policy denial, revocation, vault-ref redaction, and remote boundary status.
- Added `packages/runtime-daemon/src/model-mounting/vault-port.mjs`.
- Moved the Agentgres local vault port, encrypted keychain vault material adapter, env adapter factory, and vault-ref env alias helper out of `model-mounting.mjs`.
- Added focused vault port tests for encrypted persistence without plaintext, partial env fail-closed status, env alias resolution, public metadata redaction, audit redaction, bind/list/remove behavior, and non-persistent metadata serialization.
- Added `packages/runtime-daemon/src/model-mounting/oauth-credential-provider.mjs`.
- Moved OAuth authorization, token exchange, refresh, revoke, and access-header orchestration out of `model-mounting.mjs` while reusing the existing OAuth boundary helpers.
- Added focused OAuth credential provider tests for vault-bound authorization state, redacted authorization URLs, callback fail-closed behavior, client-secret vault policy, and revoke cleanup.
- Added `packages/runtime-daemon/src/model-mounting/projections.mjs`.
- Moved model-mounting product projection assembly, authority snapshot assembly, adapter-boundary projection, receipt replay linkage, and route-decision projection derivation out of `model-mounting.mjs`.
- Added focused projection tests for category bucketing, operation watermarking, authority summaries, adapter boundaries, receipt replay links, and route-decision derivation.
- Added `packages/runtime-daemon/src/model-mounting/read-model.mjs`.
- Moved read-only model-mounting list accessors, product/OpenAI model list projections, provider health listing, and snapshot category assembly out of `model-mounting.mjs` behind existing `ModelMountingState` methods.
- Added `packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs`.
- Moved model-mounting read-list, snapshot, authority snapshot, projection, adapter-boundary, receipt replay, and route-decision compatibility wrappers out of `model-mounting.mjs` while preserving product artifact filtering, vault-safe provider projection, schema versions, and receipt replay links.
- Added focused read-projection-facade tests for product-safe list delegation, capability projection, snapshots, projection summary, receipt replay, and authority snapshot composition.
- Added `packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs`.
- Moved catalog import URL orchestration and model download job materialization out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState.catalogImportUrl()` and `ModelMountingState.downloadModel()` delegates, while preserving live catalog/download gates, external transfer approval policy, receipt envelopes, fixture materialization, transfer retry metadata, artifact projection, and generated evidence separation.
- Added focused catalog-download operation tests for fixture import handoff, live-source fail-closed gating, queued and simulated-failure jobs, completed fixture artifact writes, and live-transfer failure metadata.
- Added `packages/runtime-daemon/src/model-mounting/provider-registry.mjs`.
- Moved hosted provider shaping, public provider redaction/vault-boundary projection, and route string validation helpers out of `model-mounting.mjs` behind compatibility wrappers.
- Added `packages/runtime-daemon/src/model-mounting/provider-registry-bindings.mjs`.
- Moved the remaining `model-mounting.mjs` provider-registry compatibility binding wrappers into a dependency-injected factory so the root imports provider projection and route-string validation behavior through an explicit module boundary.
- Added `packages/runtime-daemon/src/model-mounting/server-control.mjs`.
- Moved model gateway/server status, start/stop/restart control state, lifecycle operation receipts, redacted server log/event projection, and server log ring-buffer writes out of `model-mounting.mjs` behind existing `ModelMountingState` methods.
- Added focused server-control tests for status projection, lifecycle state/receipt/log writes, restart previous-state capture, redacted log/event reads, and limit bounding.
- Added `packages/runtime-daemon/src/model-mounting/schema-relations.mjs`.
- Moved model-mounting relation schema metadata out of `ModelMountingState.writeSchemaRelationSchemas()` and added focused tests for canonical relation names and compatibility-critical fields.
- Added `packages/runtime-daemon/src/model-mounting/default-records.mjs`.
- Moved default provider, fixture artifact, fixture endpoint, route, LM Studio detected artifact, and backend registry record construction out of `model-mounting.mjs` while keeping stateful discovery/pruning/persistence on `ModelMountingState`.
- Added focused default-record tests for compatibility ids, hosted/local boundary status, route denials, provider-derived LM Studio artifact state, and backend process status projection.
- Added `packages/runtime-daemon/src/model-mounting/validation.mjs`.
- Moved continuation route/endpoint/model safety checks and workflow Receipt Gate validation out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState` wrappers.
- Added focused validation tests for continuation modes, unsafe route mismatch blocking, Receipt Gate pass receipts, and Receipt Gate mismatch/tool-link failures.
- Added `packages/runtime-daemon/src/model-mounting/routes.mjs`.
- Moved route record normalization, explicit model endpoint ordering/mount fallback, route policy selection, model route-selection receipt shaping, and route test mutation/receipt persistence out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState` wrappers.
- Added focused route helper tests for route aliases, fallback endpoint ordering, explicit-model auto-mount, policy rejection reasons, route blocker details, route-decision receipt metadata, and route test selection/write behavior.
- Added `packages/runtime-daemon/src/model-mounting/state-seeding.mjs`.
- Moved default model-mounting bootstrap orchestration for local/native providers, LM Studio discovery, runtime provider defaults, backend seeding, fixture artifact/endpoint seeding, and default routes out of `model-mounting.mjs` behind the existing `ModelMountingState.seedDefaults()` compatibility method.
- Added focused state-seeding tests for fixture-enabled defaults, disabled-fixture pruning, LM Studio detected-artifact fallback, and discovered LM Studio artifact precedence.
- Added `packages/runtime-daemon/src/model-mounting/state-persistence.mjs`.
- Moved the model-mounting directory-to-map persistence table, map loading, whole-state write ordering, write-map delegation, and vault-ref metadata refresh out of `model-mounting.mjs` behind existing `ModelMountingState.load()`, `loadMap()`, `writeAll()`, `writeMap()`, and `writeVaultRefs()` compatibility methods.
- Added focused state-persistence tests for load filtering, canonical map coverage, whole-state write ordering, vault-ref refresh, and store delegation.
- Added `packages/runtime-daemon/src/model-mounting/loaded-instances.mjs`.
- Moved loaded model instance lookup, idle TTL eviction, loaded-instance coalescing, and endpoint reload supersession out of `model-mounting.mjs` behind existing `ModelMountingState.loadedInstanceForEndpoint()`, `evictExpiredInstances()`, `coalesceLoadedInstances()`, and `supersedeLoadedInstances()` compatibility methods.
- Added focused loaded-instance tests for nullable/error lookup modes, idle eviction receipts/write behavior, no-op eviction skips, newest-instance coalescing, and explicit supersession return values.
- Added `packages/runtime-daemon/src/model-mounting/runtime-engines.mjs`.
- Moved runtime-engine preference projection, endpoint backend preference override, runtime-engine profile/default-load-option accessors, engine list/detail projection, operator selection, profile update, profile removal, and operator profile application out of `model-mounting.mjs` behind existing `ModelMountingState.runtime*` compatibility methods.
- Added focused runtime-engine tests for default and endpoint preferences, profile priority/disable projection, selection persistence, disabled-engine preference reset, detail projection, and override removal.
- Added `packages/runtime-daemon/src/model-mounting/runtime-survey.mjs`.
- Moved runtime survey receipt projection, latest runtime survey fallback/projection, LM Studio runtime list probing, and LM Studio runtime survey probing out of `model-mounting.mjs` behind existing `ModelMountingState.runtimeSurvey()`, `latestRuntimeSurvey()`, `lmStudioRuntimeEngines()`, and `lmStudioRuntimeSurvey()` compatibility methods.
- Added focused runtime-survey tests for checked/not-checked survey projection, selected-engine receipts, LM Studio runtime list hashing, disabled/missing CLI fallbacks, and blocked survey error hashing without raw stderr leakage.
- Added `packages/runtime-daemon/src/model-mounting/default-discovery.mjs`.
- Moved native-local fixture artifact materialization, LM Studio provider discovery, LM Studio artifact discovery, LM Studio public projection pruning, and internal fixture projection pruning out of `model-mounting.mjs` behind existing default-seeding compatibility methods.
- Added focused default-discovery tests for fixture artifact metadata/materialization, disabled/running/configured LM Studio provider states, LM Studio artifact discovery gates, and pruning of LM Studio/fixture artifacts, endpoints, and instances.
- Added `packages/runtime-daemon/src/model-mounting/backend-processes.mjs`.
- Moved backend registry lookup, public backend-process snapshot projection, redacted backend command args, supervised spawn args, and supervision support predicates out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused backend-process tests for missing-backend errors, snapshot defaults, redacted artifact args, native/vLLM args, raw supervised spawn paths, unsupported-backend fallback args, and supervision support boundaries.
- Added `packages/runtime-daemon/src/model-mounting/backend-lifecycle.mjs`.
- Moved backend process ensure/touch/start/spawn/stop behavior, backend health/start/stop operations, and backend log reads out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused backend-lifecycle tests for stale process touch recovery, deterministic fixture process starts, fake subprocess output/exit handling, clean process stop, backend health/start/stop receipts, external-blocker start failures, and backend log projection.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.mjs`.
- Moved catalog provider OAuth start/callback/exchange/refresh/revoke orchestration out of `model-mounting.mjs` behind existing compatibility methods while preserving vault writes, receipts, public provider config projection, and fail-closed missing-session errors.
- Added focused catalog-provider-oauth tests for pending authorization persistence, callback state-hash lookup, exchange persistence, refresh/revoke boundary updates, and missing-session 404 envelopes.
- Added `packages/runtime-daemon/src/model-mounting/provider-operations.mjs`.
- Moved provider upsert, provider secret-ref normalization, provider health, provider model/loaded listing, and provider start/stop orchestration out of `model-mounting.mjs` behind existing compatibility methods while preserving public provider redaction and fail-closed health envelopes.
- Added focused provider-operation tests for vault-bound upsert, plaintext secret rejection, health success/failure persistence, model/loaded fallbacks, and stateless start/stop receipts.
- Added `packages/runtime-daemon/src/model-mounting/catalog-operations.mjs`.
- Moved model storage summary, catalog status projection, catalog search aggregation, and catalog entry enrichment out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused catalog-operation tests for quota/orphan accounting, status projection, search normalization/result aggregation, and enrichment dependency flow.
- Added `packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs`.
- Moved local artifact import dry-run/materialization plus endpoint mount/unmount state transitions out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused artifact-endpoint operation tests for dry-run imports, materialized local imports, endpoint mount derivation, explicit provider fallback, and unmount receipts.
- Added `packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs`.
- Moved model load, load-estimate, and unload state transitions out of `model-mounting.mjs` behind existing compatibility methods while preserving runtime-engine defaults, backend estimates, provider driver calls, supersession, and receipts.
- Added focused model-loading operation tests for estimate-only loads, persisted loaded instances, native resource estimates, and unload evidence receipts.
- Added `packages/runtime-daemon/src/model-mounting/storage-operations.mjs`.
- Moved download status/cancel, model artifact deletion, and model storage cleanup out of `model-mounting.mjs` behind existing compatibility methods while preserving destructive-confirmation, cleanup, projection, and receipt behavior.
- Added focused storage-operation tests for missing download jobs, cancel cleanup, terminal download preservation, artifact dry-run/delete/conflict behavior, and confirmed orphan cleanup.
- Added `packages/runtime-daemon/src/model-mounting/tokenizer-operations.mjs`.
- Moved model tokenization, token counting, context-fit estimation, and endpoint context-window fallback out of `model-mounting.mjs` behind existing compatibility methods while preserving route receipts, redacted input hashes, and public response envelopes.
- Added focused tokenizer-operation tests for route/receipt updates, token/count envelopes, keep-tail context fitting, and context-window fallback order.
- Added `packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.mjs`.
- Moved ephemeral MCP integration compilation, MCP server import/normalization/listing, MCP tool invocation, and workflow-node dispatch out of `model-mounting.mjs` behind existing compatibility methods while preserving vault-ref policy, tool narrowing, receipt envelopes, and workflow memory-write blocking.
- Added focused MCP/workflow operation tests for vault-ref redaction, MCP import/listing, allowed-tool policy, ephemeral tool receipts, router/MCP/Receipt Gate/model dispatch, and memory policy rejection.
- Added `packages/runtime-daemon/src/model-mounting/conversation-operations.mjs`.
- Moved response id allocation, previous-response lookup, redacted conversation-state persistence, streamed-response completion receipts, and conversation listing out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused conversation-operation tests for continuation collisions/missing responses, replay-safe redacted records, stream completion finalization, and created-at sorting.
- Added `packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs`.
- Moved model invocation and native stream-start orchestration out of `model-mounting.mjs` behind compatibility-preserving `ModelMountingState.invokeModel()` and `ModelMountingState.startModelStream()` delegates, while preserving route selection, continuation safety, in-flight coalescing, provider request shaping, receipt details, stream fallback behavior, MCP receipt linkage, and route last-selection persistence.
- Added focused model-invocation tests for capability mapping, provider invocation receipts, response-state finalization, in-flight coalescing receipts, native stream receipts without invoke-only envelope drift, stream request-shape tracing, and non-stream fallback.
- Added `packages/runtime-daemon/src/model-mounting/state-accessors.mjs`.
- Moved provider/endpoint/instance/route lookup, endpoint resolution, and ensure-loaded refresh/load behavior out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused state-accessor tests for lookup errors, endpoint mount fallback, unavailable endpoint errors, loaded-instance refresh, and load fallback.
- Added `packages/runtime-daemon/src/model-mounting/backend-registry-state.mjs`.
- Moved backend registry seeding/derivation, stored/derived backend projection merging, backend-process reconciliation, backend-process lookup, and backend log writes out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused backend-registry-state tests for environment/discovery derivation, stored-record merging, process projection, stale boot reconciliation, newest-process lookup, and redacted backend log mirroring.
- Added `packages/runtime-daemon/src/model-mounting/catalog-provider-configuration-operations.mjs`.
- Moved catalog provider configuration list/get/update, public config projection, configuration receipt persistence, and vault-backed catalog provider runtime material resolution out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused catalog-provider configuration operation tests for configurable-provider public records, persisted write/projection/receipt behavior, vault material resolution, missing material preservation, and fail-closed vault errors.
- Added `packages/runtime-daemon/src/model-mounting/vault-operations.mjs`.
- Moved vault ref binding, vault metadata/status/health projection, vault ref removal, vault metadata persistence triggers, and vault receipt emission out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused vault-operation tests for bind/remove persistence, redacted receipt emission, health/status projection, list/metadata delegation, and required field errors.
- Added `packages/runtime-daemon/src/model-mounting/huggingface-catalog-search.mjs`.
- Moved Hugging Face catalog live-search gating, auth-header application, HTTP response shaping, payload alias normalization, format/quantization filtering, auth evidence projection, and fail-closed error envelopes out of `model-mounting.mjs` behind the existing `ModelMountingState.searchHuggingFaceCatalog()` compatibility delegate.
- Added focused Hugging Face catalog-search tests for disabled/gated envelopes, successful filtered search with auth evidence, HTTP degradation, fail-closed auth errors, and payload alias normalization.
- Added `packages/runtime-daemon/src/model-mounting/capability-token-operations.mjs`.
- Moved capability token creation, public token listing, token revocation, bearer-token lookup, scope authorization, grant receipt emission, token map persistence, and public token redaction out of `model-mounting.mjs` behind existing compatibility methods.
- Added focused capability-token operation tests for public token envelopes, vault-ref redaction, grant persistence, authorize/revoke state updates, auth errors, not-found errors, and receipt emission.
- Extended `packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs` to own latest provider/vault health projection envelopes behind `ModelMountingState.latestProviderHealth()` and `ModelMountingState.latestVaultHealth()` compatibility delegates.
- Extended focused read-projection-facade tests for latest provider/vault health envelopes, receipt replay linkage, projection watermarks, and not-found behavior.
- Extended `packages/runtime-daemon/src/model-mounting/read-model.mjs` and `read-projection-facade.mjs` to own workflow node binding projection behind the existing `ModelMountingState.workflowNodeBindings()` compatibility delegate.
- Extended `packages/runtime-daemon/src/model-mounting/state-accessors.mjs` to own model artifact lookup and provider-direct mount artifact persistence behind `ModelMountingState.getModel()` and `ModelMountingState.modelForProviderMount()` compatibility delegates.
- Extended focused read-model, read-projection-facade, and state-accessor tests for workflow binding projection, artifact lookup by id/model id, not-found behavior, provider-direct artifact persistence, persisted artifact writes, and mounted artifact shaping.
- Extended `packages/runtime-daemon/src/model-mounting/routes.mjs` to own state-level route upsert, explicit-model endpoint ordering, route selection dependency wiring, and route-selection receipt creation behind existing `ModelMountingState` compatibility delegates.
- Extended focused route tests for state-operation delegate wiring, route write persistence, explicit-model mount fallback, route selection, and route-selection receipt creation.
- Added `packages/runtime-daemon/src/model-mounting/receipt-operations.mjs`.
- Moved receipt list/get delegation, lifecycle receipt envelope creation, canonical receipt construction, redaction, store writes, and projection refresh out of `model-mounting.mjs` behind existing `ModelMountingState` compatibility delegates.
- Added focused receipt-operation tests for canonical store read delegation, lifecycle receipt envelope shape, redacted details, receipt id generation, schema versioning, store writes, and projection refresh.

Compatibility map for the latest model-mounting slices:

| Public method | Owning module | Removal / migration status |
| --- | --- | --- |
| `ModelMountingState.listCatalogProviderConfigs()` | `model-mounting/catalog-provider-configuration-operations.mjs` | Keep as public read/projection delegate until route and projection callers have a deliberate migration plan. |
| `ModelMountingState.getCatalogProviderConfig()` | `model-mounting/catalog-provider-configuration-operations.mjs` | Keep as route-facing delegate for `/catalog/providers/{provider_id}/config`. |
| `ModelMountingState.configureCatalogProvider()` | `model-mounting/catalog-provider-configuration-operations.mjs` | Keep as route-facing mutation delegate so receipt/projection envelopes remain stable. |
| `ModelMountingState.catalogProviderConfig()` | `model-mounting/catalog-provider-configuration-operations.mjs` | Keep as private compatibility delegate while OAuth, catalog ports, and catalog search still call the root state facade. |
| `ModelMountingState.catalogProviderRuntimeMaterial()` | `model-mounting/catalog-provider-configuration-operations.mjs` | Keep as private compatibility delegate while catalog OAuth, config projection, and provider health callers share fail-closed runtime material semantics. |
| `ModelMountingState.bindVaultRef()` | `model-mounting/vault-operations.mjs` | Keep as route-facing mutation delegate so vault receipts, metadata persistence, and projection refresh behavior remain stable. |
| `ModelMountingState.listVaultRefs()` | `model-mounting/vault-operations.mjs` | Keep as public read delegate for vault metadata projection. |
| `ModelMountingState.vaultRefMetadata()` | `model-mounting/vault-operations.mjs` | Keep as public read delegate for redacted vault-ref lookup. |
| `ModelMountingState.vaultStatus()` | `model-mounting/vault-operations.mjs` | Keep as public read delegate for adapter status projection. |
| `ModelMountingState.vaultHealth()` | `model-mounting/vault-operations.mjs` | Keep as public read/check delegate so vault health receipts remain route-compatible. |
| `ModelMountingState.removeVaultRef()` | `model-mounting/vault-operations.mjs` | Keep as route-facing mutation delegate so removal receipts, metadata persistence, and projection refresh behavior remain stable. |
| `ModelMountingState.searchHuggingFaceCatalog()` | `model-mounting/huggingface-catalog-search.mjs` | Keep as compatibility delegate while `huggingFaceCatalogProviderPort()` still calls through the state facade. |
| `ModelMountingState.createToken()` | `model-mounting/capability-token-operations.mjs` | Keep as route-facing delegate so grant receipts, token redaction, and wallet authority audit behavior remain stable. |
| `ModelMountingState.listTokens()` | `model-mounting/capability-token-operations.mjs` | Keep as public read delegate for product-safe token projections. |
| `ModelMountingState.revokeToken()` | `model-mounting/capability-token-operations.mjs` | Keep as route-facing delegate so revocation receipts and wallet authority state remain stable. |
| `ModelMountingState.authorize()` | `model-mounting/capability-token-operations.mjs` | Keep as private compatibility delegate while model invocation, tokenizer, and MCP workflow operations share the same bearer-token authorization behavior. |
| `ModelMountingState.latestProviderHealth()` | `model-mounting/read-projection-facade.mjs` | Keep as public read/projection delegate so provider-health route envelopes, receipt replay, and projection watermarks stay route-compatible. |
| `ModelMountingState.latestVaultHealth()` | `model-mounting/read-projection-facade.mjs` | Keep as public read/projection delegate so vault-health route envelopes, receipt replay, and projection watermarks stay route-compatible. |
| `ModelMountingState.workflowNodeBindings()` | `model-mounting/read-projection-facade.mjs` / `model-mounting/read-model.mjs` | Keep as public product projection delegate so snapshot/projection workflow binding envelopes remain stable. |
| `ModelMountingState.getModel()` | `model-mounting/state-accessors.mjs` | Keep as private compatibility delegate while loading, storage, local-driver, and endpoint-operation modules still call through the state facade. |
| `ModelMountingState.modelForProviderMount()` | `model-mounting/state-accessors.mjs` | Keep as private compatibility delegate while endpoint mounting preserves provider-direct artifact persistence and call sites are still state-facade based. |
| `ModelMountingState.upsertRoute()` | `model-mounting/routes.mjs` | Keep as route-facing mutation delegate so route record normalization, persistence, and map writes remain stable. |
| `ModelMountingState.endpointIdsForExplicitModel()` | `model-mounting/routes.mjs` | Keep as private compatibility delegate while route selection still calls through state facade and can auto-mount explicit model endpoints. |
| `ModelMountingState.selectRoute()` | `model-mounting/routes.mjs` | Keep as private compatibility delegate while invocation, stream, workflow, and test-route callers share the same route policy behavior. |
| `ModelMountingState.routeSelectionReceipt()` | `model-mounting/routes.mjs` | Keep as private compatibility delegate so route-selection receipt envelopes, workflow metadata, evidence refs, and model-route decision fields remain stable. |
| `ModelMountingState.listReceipts()` | `model-mounting/receipt-operations.mjs` | Keep as public read delegate because projections, replay, receipt gates, and runtime survey surfaces rely on canonical receipt listing. |
| `ModelMountingState.getReceipt()` | `model-mounting/receipt-operations.mjs` | Keep as public read delegate because receipt replay and Receipt Gate validation rely on canonical receipt lookup. |
| `ModelMountingState.lifecycleReceipt()` | `model-mounting/receipt-operations.mjs` | Keep as private compatibility delegate while operation modules continue emitting stable lifecycle receipt envelopes through the state facade. |
| `ModelMountingState.receipt()` | `model-mounting/receipt-operations.mjs` | Keep as private compatibility delegate while operation modules continue sharing canonical receipt id/schema/redaction/write/projection semantics. |

Status: `model-mounting.mjs` is now primarily a compatibility facade plus state/storage/server/backend wrappers. Latest provider/vault health projection and workflow node binding projection now live in the read projection facade, direct model lookup/provider-mount artifact persistence now lives in state accessors, route state-operation wiring now lives in `routes.mjs`, and canonical receipt construction now lives in `receipt-operations.mjs`. Safe next extractions are any leftover state/storage/server/backend wrappers whose ownership is clear enough to isolate.

### Rust Runtime Hot Spot

- Added `crates/services/src/agentic/runtime/service/decision_loop/retry_limits.rs`.
- Moved the explicit retry failure ceiling and terminal retry-limit status into a named helper module.
- Preserved the important contract: zero budget remains an unset budget and does not trip retry-limit failure before the consecutive-failure ceiling.
- Added `crates/services/src/agentic/runtime/service/decision_loop/cognition/final_reply_product_handoff.rs`.
- Moved final-reply product handoff sanitization, direct-chat reply unwrapping/cycle collapse, internal runtime marker redaction, disposable path/URL cleanup, and product-facing raw-output rejection reasons out of `final_reply.rs`.
- Preserved the existing `cognition` module re-exports so final-reply tests and call sites keep using the same internal function names while the implementation now lives behind a focused module.
- Added `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome/terminal_reply_classification.rs`.
- Moved terminal chat reply/source-candidate/tool-plan classification, workspace contextual-answer detection, and file-mutation policy-report detection out of the `tool_outcome` support include while preserving the parent-module helper names used by tests and outcome handling.
- Added `crates/services/src/agentic/runtime/service/tool_execution/processing/phases/finalize_action_processing/completion_guards.rs`.
- Moved finalize-action duplicate/no-op guards, read-only workspace duplicate detection, browser-surface release predicate, web-pipeline completion labels, product handoff violation message construction, and file-edit patch-miss receipt evidence shaping out of `finalize_action_processing.rs` while preserving parent-module helper names for tests.
- Added `crates/services/src/agentic/runtime/service/queue/support/pipeline/facts/market_quote.rs`.
- Moved market-quote source grading, structured metric coverage counts, comparison-context counts, quote-grounding floors, and pending quote-grounding readiness out of `facts.rs` behind a crate-visible re-export so existing queue/final-reply call sites keep their public path.
- Added `crates/services/src/agentic/runtime/execution/filesystem/handler/policy.rs`.
- Moved filesystem handler patch failure classification, workspace read/write boundary wrappers, and safe regular-file read/write target guards out of `handler.rs` while preserving handler-module helper names used by policy tests and filesystem tool handling.
- Added `crates/services/src/agentic/runtime/substrate/semantic_impact.rs`.
- Moved substrate semantic-impact projection, changed-path classification, mutating-tool detection, and targeted test-selection hints out of `substrate.rs` while preserving the public `RuntimeSubstrateSnapshot` projection API and substrate test behavior.
- Added `crates/services/src/agentic/runtime/substrate/session_lifecycle.rs`.
- Moved substrate session trace bundle projection, workflow envelope adapter projection, harness trace adapter projection, and operator interruption contract projection out of `substrate.rs` while preserving the public `RuntimeSubstrateSnapshot` projection API and substrate test behavior.

## Naming And Vocabulary Decisions

- Kept public/product names stable: Agent Studio command ids, `ioi.*` command ids, data-testids, daemon routes, and request/response envelopes were not renamed.
- Treat the Stage 8 manual-auth handoff fixture as managed-session/operator-control and reconnect coverage only. It is intentionally not a real login, credential, CAPTCHA, payment, or approval-policy proof; future auth durability should use a separate local HTTP auth fixture with cookie/session behavior.
- Added `internal-docs/prompts` to `.gitignore` and removed tracked prompt files from the next tree so local prompt material stays out of `master`.
- Removed generated `docs/evidence/` artifacts from the tracked tree while keeping the ignored local evidence directory available for reruns.
- Introduced private/module-level names that describe ownership boundaries:
  - `public-text-sanitizer`
  - `studio/projection-managed-sessions`
  - `studio/projection-replay`
  - `commands/studio-test-hooks`
  - `workbench/context-snapshot`
  - `runtime-request-metadata`
  - `threads/thread-runtime-controls`
  - `threads/context-budget-policy`
  - `repository-context`
  - `http/public-runtime-routes`
  - `model-mounting/environment`
  - `model-mounting/default-discovery`
  - `model-mounting/provider-auth`
  - `model-mounting/oauth-boundary`
  - `repository-workflow-projections`
  - `model-mounting/catalog-provider-config`
  - `model-mounting/catalog-provider-ports`
  - `model-mounting/protocol-responses`
  - `model-mounting/provider-protocol`
  - `model-mounting/local-system-probes`
  - `model-mounting/provider-driver-helpers`
  - `model-mounting/provider-driver-factory`
  - `model-mounting/load-policy`
  - `model-mounting/native-local-fixture`
  - `model-mounting/provider-transport`
  - `model-mounting/provider-local-drivers`
  - `model-mounting/provider-openai-compatible-driver`
  - `model-mounting/provider-ollama-driver`
  - `model-mounting/provider-openai-backend-drivers`
  - `model-mounting/provider-lm-studio-driver`
  - `model-mounting/wallet-authority`
  - `model-mounting/vault-port`
  - `model-mounting/oauth-credential-provider`
  - `cognition/final_reply_product_handoff`
  - `tool_outcome/terminal_reply_classification`
  - `finalize_action_processing/completion_guards`
  - `queue/support/pipeline/facts/market_quote`
  - `filesystem/handler/policy`
  - `substrate/semantic_impact`
  - `substrate/session_lifecycle`
  - `model-mounting/projections`
  - `model-mounting/read-projection-facade`
  - `model-mounting/runtime-engines`
  - `model-mounting/runtime-survey`
  - `model-mounting/backend-processes`
  - `model-mounting/backend-lifecycle`
  - `model-mounting/catalog-provider-oauth`
  - `model-mounting/provider-operations`
  - `model-mounting/catalog-operations`
  - `model-mounting/artifact-endpoint-operations`
  - `model-mounting/model-loading-operations`
  - `model-mounting/storage-operations`
  - `model-mounting/tokenizer-operations`
  - `model-mounting/mcp-workflow-operations`
  - `model-mounting/conversation-operations`
  - `model-mounting/state-accessors`
  - `model-mounting/backend-registry-state`
  - `model-mounting/catalog-provider-configuration-operations`
  - `model-mounting/vault-operations`
  - `model-mounting/huggingface-catalog-search`
  - `model-mounting/capability-token-operations`
  - `runtime-doctor-report`
  - `runtime-run-cancellation`
  - `runtime-thread-control-surface`
  - `runtime-subagent-surface`
  - `runtime-approval-surface`
  - `runtime-coding-tool-budget-recovery-surface`
  - `runtime-workflow-edit-surface`
  - `runtime-coding-tool-governance-surface`
  - `runtime-coding-tool-artifact-surface`
  - `runtime-coding-tool-invocation-surface`
  - `runtime-workspace-snapshot-surface`
  - `runtime-diagnostics-feedback-surface`
  - `runtime-diagnostics-repair-surface`
  - `threads/model-route-selection`
  - `threads/run-memory-resolution`
  - `threads/thread-turn-projection`
  - `studio/durability-panels`
  - `studio/policy-lease-lifecycle`
  - `studio/chat-output-renderers`
  - `studio/parity-plus-panels`
  - `studio/parity-plus-panels` Stage 5 stop/cancel/recover lifecycle helper
  - `studio/stage7-delegation-lifecycle`
  - `studio/runtime-cockpit-lifecycle`
  - `studio/thread-events`
  - `studio/thread-lifecycle`
  - `studio/runtime-controls`
  - `studio/hunk-lifecycle`
  - `workbench/shell-header`
  - `workbench/mode-body-renderers`
  - `workbench/model-snapshot`
  - `workbench/mode-controller`
  - `decision_loop/retry_limits`
  - `live-gui-proof-harness`
- Deferred disruptive mass renames until after larger ownership modules are extracted and compatibility shims can be added deliberately.

## CLI/TUI Adapter Status

CLI/TUI surfaces were not hardened in this leg because the active parity-plus product proof path remains the OpenVSCode/Agent Studio GUI plus daemon runtime. The CLI/TUI adapters should stay separately gated unless they become active product commitments. If activated, they need the same stream/replay/redaction/policy/managed-session contract checks used by the GUI proof path.

## Soak And Product-Leak Audit

- Final integrated soak for this refactor leg used the fast release gate, managed-session reconnect tests, Rust retry-limit tests, Stage 8 managed-session reconnect live GUI proof, and Stage 9 historic replay live GUI proof after the final extraction wave.
- Retry-limit behavior remained covered by the two `ioi-services` zero-budget/failure-ceiling tests.
- Replay/reconnect durability remained covered by `managed-session-inspection.test.mjs`, Stage 8 reconnect live proof, and Stage 9 historic replay live proof.
- Product UI leakage remained covered by `extension.static.test.mjs` and the Stage 9 proof check `productUiAvoidsRawEvidencePaths`; the Stage 9 proof also recorded `noLiveExecutionRequests`.
- The Stage 8 live proof initially exposed real activation-order regressions in `extension.js`; after lazy dependency wrappers were added, Stage 8 and Stage 9 both passed.

## Current Verification Snapshot

2026-06-04 baseline guardrails:

- `git status --short --branch` recorded the active refactor worktree and no generated `docs/evidence/` files staged.
- `git log --oneline --decorate -3` recorded `e5f13a68d (HEAD -> master, origin/master, origin/HEAD) Move daemon run read surface`, `21371d4f8 Move daemon task job surface`, and `03868d0ab Move skill hook and policy lease surfaces`.
- `git check-ignore -v docs/evidence/autopilot-agent-runtime-parity-plus/example.json || true` confirmed `.gitignore:40:docs/evidence/`.
- `node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js` passed.
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs` passed.
- `cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib` passed.
- `cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib` passed.

2026-06-04 integrated fast gate and live GUI proofs:

- `git log --oneline --decorate -3` passed and recorded `e5f13a68d (HEAD -> master, origin/master, origin/HEAD) Move daemon run read surface`, `21371d4f8 Move daemon task job surface`, and `03868d0ab Move skill hook and policy lease surfaces`.
- `git check-ignore -v docs/evidence/autopilot-agent-runtime-parity-plus/example.json || true` confirmed `.gitignore:40:docs/evidence/`.
- `node --check apps/autopilot/openvscode-extension/ioi-workbench/extension.js` passed after the live activation-order wrapper fix.
- `node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs` passed after the live activation-order wrapper fix.
- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs packages/runtime-daemon/src/managed-session-inspection.test.mjs` passed.
- `node --check scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs` passed.
- `node --check scripts/lib/workflow-historic-run-gui-replay-proof.mjs` passed.
- `cargo test -p ioi-services zero_budget_does_not_trip_retry_limit_before_failure_ceiling --lib` passed.
- `cargo test -p ioi-services retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget --lib` passed.
- `node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs` passed and wrote evidence to `docs/evidence/autopilot-agent-runtime-parity-plus/stage-8-browser-computer-session-runtime-polish/live-gui-managed-session-reconnect/2026-06-04T17-17-30-781Z`.
- `node scripts/lib/workflow-historic-run-gui-replay-proof.mjs` passed and wrote evidence to `docs/evidence/autopilot-agent-runtime-parity-plus/stage-9-evidence-replay-product-boundary/historic-run-gui-replay/2026-06-04T17-18-00-382Z`.
- `git diff --check` passed.

2026-06-04 daemon surface extraction checks:

- `node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-thread-event-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-conversation-artifact-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-mcp-catalog-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-mcp-serve-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-task-job-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/threads/thread-replay.test.mjs` passed.
- `node --test packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs` passed.
- `node --test packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs packages/runtime-daemon/src/threads/workspace-trust-state.test.mjs` passed.
- `node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/threads/thread-store.test.mjs packages/runtime-daemon/src/threads/thread-persistence.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/conversation-artifacts.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs` passed.
- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-context-policy-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-thread-event-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-conversation-artifact-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-mcp-control-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-mcp-serve-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-thread-control-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-subagent-surface.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon direct context compaction delegate checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-context-policy-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs packages/runtime-daemon/src/runtime-thread-control.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/managed-session-inspection.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon subagent cancellation propagation checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-subagent-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-subagent-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-subagent-surface.test.mjs packages/runtime-daemon/src/runtime-subagent-recovery.test.mjs packages/runtime-daemon/src/managed-session-inspection.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs packages/runtime-daemon/src/thread-store.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon approval surface extraction checks:

- `node --check packages/runtime-daemon/src/runtime-approval-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-approval-surface.test.mjs` passed.
- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-approval-surface.test.mjs packages/runtime-daemon/src/runtime-approval-lease.test.mjs` passed.
- `node --test packages/runtime-daemon/src/approval-lease.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs packages/runtime-daemon/src/runtime-thread-control.test.mjs` passed.
- `node --test packages/runtime-daemon/src/managed-session-inspection.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs packages/runtime-daemon/src/http/public-runtime-routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.test.mjs packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon coding-tool budget recovery surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.test.mjs packages/runtime-daemon/src/runtime-approval-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/managed-session-inspection.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon workflow-edit surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-workflow-edit-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-workflow-edit-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-workflow-edit-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-workflow-edit-surface.test.mjs packages/runtime-daemon/src/runtime-approval-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-thread-control.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon coding-tool governance surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs packages/runtime-daemon/src/runtime-approval-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.test.mjs` passed.
- `node --test packages/runtime-daemon/src/approval-lease.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs packages/runtime-daemon/src/runtime-thread-control.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon coding-tool artifact surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-results.test.mjs packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-results.test.mjs packages/runtime-daemon/src/computer-use-inputs.test.mjs packages/runtime-daemon/src/runtime-run-event-helpers.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon workspace snapshot surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs packages/runtime-daemon/src/diagnostics-feedback.test.mjs packages/runtime-daemon/src/diagnostics-repair-policy.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon diagnostics feedback surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs packages/runtime-daemon/src/diagnostics-feedback.test.mjs packages/runtime-daemon/src/diagnostics-repair-policy.test.mjs packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs` passed.
- `node --test packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon diagnostics repair decision surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs packages/runtime-daemon/src/diagnostics-feedback.test.mjs packages/runtime-daemon/src/diagnostics-repair-policy.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 daemon diagnostics repair helper expansion checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs packages/runtime-daemon/src/diagnostics-feedback.test.mjs packages/runtime-daemon/src/diagnostics-repair-policy.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs` passed.

2026-06-04 daemon coding-tool invocation surface extraction checks:

- `node --check packages/runtime-daemon/src/index.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs` passed.
- `node --check packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs` passed.
- `node --test packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-artifact-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs packages/runtime-daemon/src/runtime-diagnostics-feedback-surface.test.mjs packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs packages/runtime-daemon/src/runtime-coding-tool-results.test.mjs packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs` passed.
- `node --test packages/runtime-daemon/src/http/public-runtime-routes.test.mjs packages/runtime-daemon/src/runtime-run-read-surface.test.mjs packages/runtime-daemon/src/computer-use-inputs.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting catalog provider configuration checks:

- `node --test packages/runtime-daemon/src/model-mounting/catalog-provider-configuration-operations.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/catalog-provider-configuration-operations.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-ports.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/catalog-operations.test.mjs packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs` passed.

2026-06-04 model-mounting vault operation checks:

- `node --check packages/runtime-daemon/src/model-mounting/vault-operations.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs packages/runtime-daemon/src/model-mounting/vault-port.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/catalog-provider-configuration-operations.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-ports.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/catalog-operations.test.mjs packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs packages/runtime-daemon/src/model-mounting/provider-registry-bindings.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting Hugging Face catalog search checks:

- `node --check packages/runtime-daemon/src/model-mounting/huggingface-catalog-search.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/huggingface-catalog-search.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/huggingface-catalog-search.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/catalog-provider-ports.test.mjs packages/runtime-daemon/src/model-mounting/catalog-operations.test.mjs packages/runtime-daemon/src/model-mounting/catalog-projections.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/catalog-provider-configuration-operations.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/provider-registry-bindings.test.mjs packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting capability token operation checks:

- `node --check packages/runtime-daemon/src/model-mounting/capability-token-operations.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/tokenizer-operations.test.mjs packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/inflight-invocation.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/read-model.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs packages/runtime-daemon/src/model-mounting/provider-registry-bindings.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting latest health projection checks:

- `node --check packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-model.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting read/accessor facade checks:

- `node --check packages/runtime-daemon/src/model-mounting/read-model.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/state-accessors.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/read-model.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/state-accessors.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-model.test.mjs packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/state-accessors.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/product-defaults.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting route state-operation checks:

- `node --check packages/runtime-daemon/src/model-mounting/routes.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs` passed.
- `git diff --check` passed.

2026-06-04 model-mounting receipt operation checks:

- `node --check packages/runtime-daemon/src/model-mounting/receipt-operations.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs` passed.
- `node --check packages/runtime-daemon/src/model-mounting.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs packages/runtime-daemon/src/model-mounting/routes.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs packages/runtime-daemon/src/model-mounting/server-control.test.mjs` passed.
- `node --test packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs packages/runtime-daemon/src/model-mounting/projections.test.mjs packages/runtime-daemon/src/model-mounting/runtime-survey.test.mjs` passed.
- `git diff --check` passed.

## Remaining Follow-Ups

- Reduce `extension.js` further by moving Studio projection events, managed-session controls, panel lifecycle, and feature command groups.
- Reduce `packages/runtime-daemon/src/index.mjs` by extracting service lifecycle, route registration glue, and the remaining state-store orchestration that is still too large for easy review.
- Reduce `model-mounting.mjs` further by moving any leftover state/storage/server/backend wrappers whose ownership is now clear enough to isolate.
- Continue Rust hot-spot splits around final reply contract, tool outcome classification, finalize action processing, queue facts, filesystem handler, and substrate lifecycle.
- After future extraction waves, rerun the integrated gate and live GUI proofs to keep watching retry-limit, replay/reconnect durability, and product UI leakage under real use.
