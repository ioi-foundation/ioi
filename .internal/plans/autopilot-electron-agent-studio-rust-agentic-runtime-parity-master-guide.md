# Autopilot Electron Agent Studio Rust Agentic Runtime Parity Master Guide

Owner: Autopilot Workbench / Agent Studio / Electron VS Code fork / `ioi-workbench` / Rust agentic runtime / JS runtime daemon / model mounting / tracing / validation harness

Status: source-of-truth guide; target Rust agentic runtime parity proof achieved; broader feature-family parity remains follow-on scope

Created: 2026-05-24

Last updated: 2026-05-24

Primary references:

- `.internal/plans/autopilot-electron-agent-studio-runtime-ux-denoising-tracing-separation-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-runtime-cockpit-parity-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-chat-ux-playwright-hardening-master-guide.md`
- `.internal/plans/autopilot-electron-model-mounting-daemon-runtime-adapter-master-guide.md`
- `crates/types/src/app/agentic/tools/agent_tool.rs`
- `crates/services/src/agentic/runtime/service/decision_loop/cognition/mod.rs`
- `crates/services/src/agentic/runtime/tools/builtins/web_retrieval.rs`
- `packages/runtime-daemon/src/index.mjs`
- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js`

## Executive Verdict

Electron Agent Studio now has passing bridge-level proof that default Agent Mode can route through daemon-owned agent turns into the Rust agentic runtime while using the daemon model mounting route for reasoning.

The latest validation proves the critical split-brain repair:

- Agent Mode uses the daemon agent-turn path instead of silently calling `/v1/chat/completions`.
- Direct `/v1/chat/completions` remains isolated to explicit Ask/direct-model mode.
- The Rust bridge attaches to the IOI daemon model mounting route and does not use direct provider fallback.
- The runtime streams real reasoning deltas, tool route decisions, receipts, `web__search`, `web__read`, and final chat output.
- Current/source-sensitive prompts no longer pass by stale model prose alone.

The target end state is:

```text
Agent Studio prompt
  -> daemon-owned agent turn
  -> Rust agentic decision loop
  -> model route for reasoning/streaming
  -> typed tool proposals and execution events
  -> policy, approvals, receipts, replay, tracing
  -> calm Studio projection
```

Direct model completions should remain available as explicit Ask/direct-model mode, but they must not be confused with Autopilot's governed autonomous execution path.

This guide exists to remove the split-brain between:

- Electron/JS model mounting daemon as the active Studio chat path;
- Rust full agentic runtime as the richer execution authority.

## Current Validation Status - 2026-05-24

The target parity proof is achieved in the latest run.

Implemented:

- Agent Studio source now distinguishes Agent Mode from explicit Ask/direct-model mode.
- Default Agent Mode now routes through daemon-owned agent turns instead of silently calling `/v1/chat/completions`.
- Direct `/v1/chat/completions` is isolated to the Ask helper path.
- The fork-native Agent Mode picker now treats `ask` as the direct-model execution mode instead of falling back to Agent.
- Current/source-sensitive prompts in Agent Mode fail closed if the agent turn does not emit retrieval events.
- Plain text answer handling no longer treats ordinary prose as proof of work.
- The Rust `ioi-runtime-bridge` now accepts a real HTTP inference backend only through daemon route configuration:
  - `IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL`
  - `IOI_RUNTIME_AGENT_SERVICE_MODEL`
  - `IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID`
  - `IOI_RUNTIME_INFERENCE_URL`
  - `IOI_RUNTIME_MODEL`
- Direct `LOCAL_LLM_*`, `OPENAI_API_KEY`, LM Studio, Ollama, or provider-native fallback inference is intentionally removed from the Agent Studio runtime parity bridge path.
- The validation harness now bootstraps the IOI daemon model mounting layer: it starts the daemon, imports a native local artifact, mounts and loads it through the model runtime API, creates a local-only daemon model route, verifies the route, and passes only the daemon OpenAI-compatible endpoint, daemon token, route id, and daemon model id into the Rust bridge.
- The Rust inference adapter no longer rewrites the daemon OpenAI-compatible `/v1/chat/completions` route into Ollama native `/api/chat` unless explicitly opted in or the endpoint is the Ollama default port.
- The parity harness rebuilds the Rust bridge when relevant Rust inference, bridge, cognition, or deterministic web-read fixture sources are newer than `target/debug/ioi-runtime-bridge`.
- The native local model fixture now emits deterministic query-binding, intent-ranking, tool-call, and token-stream behavior for the simple and retrieval probe turns.
- The deterministic web fixture now supports the full `web__search` -> `web__read` -> `chat__reply` path for the AKT/Filecoin probe.
- The live Electron launcher now wires `RuntimeAgentService` bridge settings into the managed daemon before daemon startup, and builds the default Rust bridge binary first when a dev checkout has not built it yet.
- The live Electron launcher now wires daemon-backed inference settings into the Rust bridge after the daemon endpoint/token are created, using `route.local-first` so Studio's selected route and the bridge route agree.
- The RuntimeAgentService command adapter now lets bridge invocations inherit the current process environment at call time, which closes the ordering gap where the daemon adapter was constructed before the launcher knew the daemon inference endpoint/token.
- The Rust cognition prompt now uses a compact non-browser tool surface for unresolved/general turns, preventing local OpenAI-compatible runtimes from receiving the full diagnostic tool catalog for ordinary chat.
- The local OpenAI-compatible inference adapter now sends `reasoning_effort: "none"` by default for real local runtimes, including Qwen-family LM Studio routes, while preserving explicit operator overrides.
- Agent Studio now auto-detects reasoning-capable selected models/routes and shows a reasoning effort selector only for those selections. The selector defaults to `none` and passes the chosen effort into Ask streams and Agent Mode model options.
- The daemon thread thinking control now accepts `none`, alongside `low`, `medium`, `high`, and `xhigh`.
- The Rust bridge submit-turn loop now honors the thread's remaining step budget instead of silently attempting ten bridge steps and outliving the daemon bridge timeout.
- Short plain unknown utterances can complete through the existing direct-inline `chat__reply` path, while currentness/retrieval/market/repository-like unknown requests remain on the agentic tool path.
- Lightweight conversational backchannels such as greetings, thanks, acknowledgements, laughter, and social check-ins now emit canonical `chat__reply` without invoking the direct-inline author model; richer conversational prose still uses the model-authored direct-inline path.
- Runtime daemon turn envelopes now project the bridge run result back as `result`/`output`/`text`, and Agent Studio also recovers assistant text from `chat__reply` tool events. This closes the live UI case where Agent Mode completed but showed "completed without additional assistant text."
- The Rust `RuntimeAgentService` bridge now bounds each Agent turn and each Agent step, failing with `runtime_bridge_turn_timeout`, `runtime_bridge_step_timeout`, or `runtime_bridge_no_progress` before the daemon adapter's 120s command timeout when a local model returns no executable agent action.

Important correction:

LM Studio can remain one provider behind the daemon-owned Models surface, but it is not a valid fallback authority or bootstrap mechanism for Agent Studio runtime parity. The tested Agent Studio/Rust path must use IOI's own model mounting and routing infrastructure because that is where policy, receipts, route selection, provider eligibility, and load/unload authority live.

Latest evidence:

- `docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/2026-05-24T19-59-50-242Z/proof.json`
- `docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/2026-05-24T19-59-50-242Z/rust-runtime-bridge-probe.json`
- `docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/2026-05-24T19-59-50-242Z/process-cleanup.json`
- `docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/2026-05-24T19-59-50-242Z/live-managed-daemon-runtime-service-smoke.json`

Latest proof result:

```json
{
  "targetRustAgenticRuntimeParityAchieved": true,
  "defaultStudioUsesAgentTurnApi": true,
  "directChatCompletionsOnlyInChatOnlyMode": true,
  "daemonModelMountingBootstrapSucceeded": true,
  "daemonModelRouteResolved": true,
  "rustBridgeUsedDaemonModelRoute": true,
  "directProviderFallbackUsed": false,
  "rustRuntimeBridgeAttached": true,
  "realAgentEventStreamingObserved": true,
  "modelTokenStreamingObserved": true,
  "webSearchObserved": true,
  "webReadObserved": true,
  "retrievalRequiredPromptDidNotUseStaleModelProse": true,
  "agentModeFailsClosedWhenRuntimeUnavailable": true,
  "plainTextTurnHasNoPermanentWorkedRecord": true,
  "workRecordOnlyAppearsForRealToolOrExplorationTurns": true,
  "documentOfRecordObservedForAgenticWork": true,
  "traceLinksOpenExactSteps": true,
  "verifiedBadgesRequireReceiptRefs": true,
  "modelProseNotAcceptedAsRuntimeTruth": true,
  "noTauriUsage": true,
  "noWebviewDurableRuntimeAuthority": true,
  "noExtensionHostToolExecution": true,
  "noExternalConnectorAction": true,
  "noOrphanProcesses": true
}
```

Latest bridge probe summary:

```json
{
  "start_thread": "active",
  "submit_turn:simple": {
    "status": "completed",
    "result": "Yes, I like humans!",
    "tools": ["chat__reply"]
  },
  "submit_turn:retrieval": {
    "status": "completed",
    "result": "Based on web research, AKT is performing better than Filecoin right now.",
    "tools": ["web__search", "web__read", "chat__reply"]
  }
}
```

Current blockers:

- None for the target proof generated by `npm run goal:autopilot-agent-studio-rust-agentic-runtime-parity:run`.
- None for the live managed-daemon bridge startup path that previously produced the `RuntimeAgentService bridge is required for runtime_service profile` 424 in Agent Studio.
- None for the follow-on live managed-daemon timeout path where local Qwen/LM Studio spent the response budget without producing an executable agent action; Agent Mode now fails closed at the bridge boundary instead of waiting for the adapter timeout.

Important clarification:

This completion is the target bridge/runtime proof for this guide's current goal runner. The broader feature families below, such as browser/screen automation, native hunk review, long-running shell lifecycle, media, memory, delegation, and connector policy approvals, remain follow-on parity work unless their own proof flags are promoted into this guide's required target proof.

## Observed Failure This Guide Fixed In The Target Proof

The previous Electron Studio path could produce a visually plausible chat answer while missing the runtime behavior that makes Autopilot valuable.

Observed failure pattern before repair:

- A current/source-sensitive prompt, such as a market comparison or investment/current-events question, returns generic model prose.
- The answer does not visibly perform `web__search` or `web__read`.
- The response has no source citations, current-date grounding, or retrieval trace.
- The model route can stream tokens, but the runtime does not stream tool events from the Rust agentic loop.
- The UI can show runtime chrome, receipts, or "worked" status without proving that a real agentic turn happened.

Root cause before repair:

- `apps/autopilot/openvscode-extension/ioi-workbench/extension.js` routed default Studio submission through `streamStudioModelCompletion`.
- `streamStudioModelCompletion` called the JS daemon's OpenAI-compatible `/v1/chat/completions` route.
- `/v1/chat/completions` is the model invocation path. It is not the Rust agentic runtime decision loop.
- The Rust runtime contains retrieval, browser/screen, shell, file, memory, policy, verification, completion, and postcondition rules that the previous default Electron Studio path did not exercise.

This is not primarily a copy problem, a prompt problem, or a UI polish problem. It is a runtime routing problem.

The product must make this impossible to confuse:

```text
Ask/direct-model answer != governed agentic execution
```

If Studio cannot access the agentic runtime for a prompt that requires retrieval, file inspection, shell execution, browser/screen action, memory, or policy-bound work, it must display a clear blocker instead of producing stale model prose.

## Non-Negotiable Canon

- Electron/VS Code fork remains the canonical Autopilot app shell.
- IOI daemon remains the authority boundary for autonomous execution.
- Rust full agentic runtime semantics are the canonical target for Agent Studio turns.
- JS model mounting remains valuable for local model catalog, LM Studio-inspired model UX, OpenAI-compatible model routes, and provider/runtime management.
- Studio is projection and typed requests only.
- Model prose is not proof of execution.
- Direct `/v1/chat/completions` is direct model invocation for Ask, not an agentic turn.
- Agentic turns must emit typed events for model tokens, tool proposals, tool execution, policy leases, command output, patch proposals, browser/screen steps, receipts, replay, stop/resume, and trace references.
- High-stakes, current, or source-sensitive questions must trigger retrieval or explicitly report that retrieval is unavailable.
- Tauri is not revived or used as a fallback.
- No live external connector action is performed in validation.

## Product Doctrine

### Models Reason, The Runtime Works

Mounted models are reasoning engines. They may generate prose, propose steps, and synthesize results. They are not, by themselves, Autopilot's execution substrate.

Autopilot's value lives in the governed runtime loop:

- classify intent;
- select model route;
- decide whether direct answer is allowed;
- select tools;
- evaluate policy;
- request approval if needed;
- execute through the daemon boundary;
- verify postconditions;
- emit receipts;
- attach replay;
- project the result into Studio.

### Retrieval Is A Runtime Requirement

Any prompt involving current facts, prices, rankings, market state, news, laws, live docs, external sources, or "which is better right now" must either:

- use retrieval with source evidence; or
- explicitly say retrieval is unavailable in the current runtime configuration.

The product must not let local-model confidence stand in for source-grounded execution.

### Plain Text Should Stay Plain

If a turn only returns plain answer text and does not use tools, files, shell, web, browser, screen, memory, policy, or patch review:

- no persistent "Worked for X seconds" record;
- no receipt badge;
- no proof card;
- no fake verified state;
- no trace link unless there is a real trace worth inspecting.

The temporary in-flight state should be a quiet line such as:

```text
Thinking about your request - 2s
```

When the answer arrives, that temporary line disappears.

### Work Should Produce A Document Of Record

When the runtime actually explores, searches, reads files, runs commands, proposes edits, or verifies output, Studio may show a compact document-of-record summary:

```text
Worked for 35s
Explored 2 files, 2 folders, 4 searches
Edited Web4Page.jsx +7 -5
Ran npm run build
Ran npm run lint
```

The full evidence remains in Tracing/Runs.

## Current State

### What Works

- Electron shell and Agent Studio surface exist.
- Composer, Add Context, Tools, model route selector, and basic chat UX are present.
- Mounted model routes can stream through the JS runtime daemon.
- Models mode can discover local model artifacts and manage daemon-backed model routes.
- Studio can project compact runtime state and link proof into Tracing/Runs.
- JS daemon exposes a small governed runtime tool catalog:
  - `fs.read`
  - `sys.exec`
  - `mcp.invoke`
  - `workspace.status`
  - `git.diff`
  - `file.inspect`
  - `file.apply_patch`
  - `test.run`
  - `lsp.diagnostics`
  - `artifact.read`
  - `tool.retrieve_result`
  - `computer_use.request_lease`

### What Is Missing From The Studio Runtime Path

The Rust agentic runtime exposes or models a much larger tool and policy universe, including:

- `web__search`
- `web__read`
- `browser__navigate`, `browser__inspect`, `browser__click`, `browser__type`, `browser__screenshot`, and related browser tools
- `screen__inspect`, `screen__click`, `screen__type`, and related GUI tools
- `shell__run`, `shell__start`, `shell__status`, `shell__input`, `shell__terminate`, `shell__reset`, `shell__cd`
- `file__read`, `file__write`, `file__edit`, `file__multi_edit`, `file__search`, `file__delete`, and related file tools
- `memory__search`, `memory__read`, `memory__append`, `memory__replace`
- `media__extract_transcript`, `media__extract_evidence`
- `software_install__resolve`, `software_install__execute_plan`
- `app__launch`
- `agent__delegate`, `agent__await`, `agent__pause`, `agent__complete`, `agent__escalate`
- `chat__reply`
- `http__fetch`, `math__eval`, clipboard, window, monitor, commerce, and wallet-adjacent primitives

### Rust Runtime Feature Families To Recover In Electron Studio

| Feature family | Why it matters | Expected Studio behavior | Evidence location |
| --- | --- | --- | --- |
| Intent classification / CIRC | Prevents casual chat, coding, browser, install, and connector requests from collapsing into one model answer path. | Prompt gets classified before runtime action; direct answer only when allowed. | Trace step and turn metadata. |
| Retrieval contract | Keeps latest/current/source-sensitive answers grounded. | Shows searching/reading progress, then cited answer. | Tracing source bundle. |
| Web search/read | Makes Studio useful for current facts and research. | Uses `web__search` and `web__read`, not browser SERPs, for retrieval work. | Search/read receipts. |
| Browser execution | Allows interactive websites when retrieval is insufficient. | Browser cards only for real browser tasks, with snapshots and verification. | Browser trace snapshots. |
| Screen/GUI execution | Allows non-browser desktop/app work. | Screen/app cards only for real GUI actions and explicit permission states. | Screen snapshots and action receipts. |
| Shell lifecycle | Makes command work observable and stoppable. | Streams stdout/stderr, exit code, duration, and postconditions. | Command log step. |
| File read/search/edit | Makes repo-aware coding real. | Reads before answering repo questions; uses native diff/hunk review for patches. | File read/edit receipts. |
| Native hunk review | Keeps code edits operator-controlled. | Accept/reject hunks inline; receipt emitted for each decision. | Patch trace and hunk receipts. |
| Diagnostics/tests | Separates "I changed it" from "it passes." | Shows concise test/diagnostic summaries in Studio. | Full logs in Tracing. |
| Memory | Lets Studio use durable remembered context correctly. | Uses `memory__search` and `memory__read` before answering memory-dependent prompts. | Memory lookup trace. |
| Media evidence | Supports transcript/evidence extraction. | Extracts media evidence when asked; does not summarize media from page metadata alone. | Media extraction bundle. |
| Software install resolver | Handles install requests safely. | Resolves install plan, shows approval, verifies app/command after install. | Install plan and approval receipts. |
| App launch | Opens local apps with verification. | Uses `app__launch` where available, verifies active/focused app. | Launch receipt and observation. |
| Delegation/workers | Enables bounded worker handoff without hiding authority. | Shows worker lanes only when real `agent__delegate` events exist. | Worker/subagent trace lanes. |
| Policy leases | Keeps consequential action bounded. | Blocks elevated/destructive work until approved; denial prevents execution. | Policy and approval receipts. |
| Stop/resume/checkpoint | Makes long tasks controllable. | Stop interrupts current turn; resume continues from daemon checkpoint. | Turn lifecycle trace. |
| Replay/receipts | Makes execution auditable. | Studio shows compact View Trace affordance; Tracing holds proof detail. | Runs/Tracing surface. |

The Rust decision-loop prompt also includes important behavioral rules that Studio currently does not receive as enforced runtime behavior:

- prefer retrieval-led reasoning;
- use `web__search` and `web__read` for latest/sources/citations;
- use `memory__search` and `memory__read` for durable remembered context;
- use `browser__*` only for interactive browser work;
- use `screen__*` for non-browser GUI work;
- verify after actions before claiming success;
- use `shell__start` for multi-command workflows;
- use `software_install__*` only for explicit install requests;
- use `agent__complete` only when the goal is achieved;
- do not use chat prose to claim planned actions or unverified execution.

## Product Problem

The current Studio UX can look like an agent while behaving like a direct model chat pipe.

That creates bad outcomes:

- current-events questions get stale model answers instead of source-grounded research;
- tool-capable asks do not reliably produce tool proposals;
- command/file/browser/action state is not represented as real daemon events;
- the user sees proof-like UI without the full proof-producing runtime;
- validation can accidentally certify UI polish instead of agentic runtime capability.

The fix is not more UI ornamentation. The fix is to route Studio through the real agentic execution contract.

## Target Behavior By Prompt Class

| Prompt class | Default Studio mode | Required behavior | Failure behavior |
| --- | --- | --- | --- |
| Greeting / simple explanation | Chat-allowed Agent Mode or explicit Ask Mode | Token-stream plain answer. No work card. | If model route unavailable, show route blocker. |
| Current market/news/law/version question | Agent Mode | Retrieval gate fires; web search/read; cited answer with absolute dates. | If retrieval unavailable, refuse stale answer and show bridge blocker. |
| Repo-aware question | Agent Mode | Read/search relevant files before answering. | If workspace tools unavailable, disclose blocker. |
| Code edit request | Agent Mode | Inspect files, propose patch, native hunk review, receipts. | No direct webview mutation. |
| Shell/test request | Agent Mode | Policy check, shell event stream, exit code, concise summary. | If denied, command does not execute. |
| Browser task | Agent Mode | Use browser tools with inspect-before-click semantics. | If browser provider unavailable, explicit blocker. |
| Desktop/app task | Agent Mode | Use screen/app tools and verify action. | If host permission missing, explicit blocker. |
| Memory question | Agent Mode | Query durable memory before answering. | If memory unavailable, disclose. |
| Workflow/build request | Agent Mode -> Workflow handoff where useful | Build plan/workflow through daemon-owned primitives. | No fixture-only claims. |
| Connector dry-run | Agent Mode | Mock/dry-run only, policy + receipts. | No live connector action. |
| Live connector action | Future connector sprint only | Requires explicit policy/approval/receipt stack. | Block in this guide. |

## Required Mode Semantics

Studio must expose and enforce two modes:

- **Agent Mode**: default. Uses daemon-owned agent turns and Rust runtime semantics.
- **Ask Mode**: explicit. Uses direct model completion for plain conversation only.

The mode selector is not cosmetic. It changes the runtime path.

Agent Mode must never silently degrade into Ask Mode for prompts that require current information, source evidence, file inspection, shell, browser/screen, memory, policy, or execution.

Ask Mode must label itself honestly and must not render receipts, verified badges, tool timelines, "worked" records, or execution claims unless the daemon actually emits proof.

## Target End State

Agent Studio supports two explicit modes:

### Agent Mode

Default for Studio.

```text
Prompt -> agent turn -> Rust loop -> model route + tools -> events -> receipts -> trace -> Studio projection
```

Agent Mode is used for:

- repo questions;
- current/research questions;
- code inspection;
- file edits;
- terminal/test work;
- workflow construction;
- browser/screen automation;
- policy-bound operations;
- connector dry-runs;
- any prompt where the user expects work, evidence, or execution.

### Ask Mode

Explicitly selected.

```text
Prompt -> direct model route -> token stream -> answer
```

Ask Mode is used for:

- casual brainstorming;
- plain language explanation;
- drafting without tool use;
- no workspace mutation;
- no current facts unless retrieval is explicitly unavailable and disclosed.

Ask responses must not display run cards, "worked for X seconds" records, receipts, or verified badges unless a real daemon event/receipt exists.

## Runtime Architecture

### Recommended Route Shape

Add a daemon-owned agent-turn API:

```text
POST /v1/threads/:thread_id/turns
GET  /v1/threads/:thread_id/turns/:turn_id
GET  /v1/threads/:thread_id/turns/:turn_id/events
POST /v1/threads/:thread_id/turns/:turn_id/stop
POST /v1/threads/:thread_id/turns/:turn_id/resume
GET  /v1/traces/:trace_id
GET  /v1/receipts/:receipt_id
```

The endpoint may initially bridge into the Rust runtime as a sidecar process, local HTTP service, FFI boundary, or command-level harness. The transport is less important than preserving one authority contract.

### Bridge Topology

The recommended bridge shape is:

```text
Electron Studio webview
  -> ioi-workbench extension command
  -> JS runtime daemon HTTP API
  -> RuntimeAgentService bridge
  -> Rust agentic runtime decision loop
  -> tool execution boundary
  -> daemon event/receipt/tracing store
  -> Studio projection
```

The JS daemon is allowed to remain the local model/runtime management process, but it must not become a second agent brain. Its job is to:

- expose stable HTTP APIs to Electron;
- own model catalog and model route state;
- host or proxy turn/event/receipt APIs;
- launch or attach the Rust runtime sidecar;
- normalize Rust events into Studio/Tracing projections;
- keep policy and receipt boundaries intact.

### Runtime Bridge Environment

Validation and launch scripts must support the Rust sidecar through environment-configurable bridge settings:

```text
IOI_RUNTIME_DAEMON_PROFILE=runtime_service
IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND=<path-to-rust-runtime-bridge>
IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS=<json-array-of-args>
IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID=<stable-local-id>
```

If these are absent, Agent Mode must report that the Rust agentic bridge is unavailable. It must not answer source-sensitive prompts through the direct model path.

### Event Stream

Agent turns must emit structured events. Minimum event types:

```text
turn.created
turn.started
model.route_selected
model.stream_started
model.token_delta
model.stream_completed
tool.proposed
tool.approval_required
tool.started
tool.stdout_delta
tool.stderr_delta
tool.completed
tool.failed
web.search_started
web.search_result
web.read_started
web.read_completed
browser.snapshot
screen.snapshot
file.patch_proposed
file.hunk_decision_required
file.hunk_accepted
file.hunk_rejected
diagnostics.started
diagnostics.completed
test.started
test.completed
receipt.emitted
trace.step_linked
turn.completed
turn.failed
turn.stopped
turn.resumed
```

Studio consumes these events. It does not infer execution from assistant prose.

### Event To UX Mapping

| Event | Studio default | Tracing/Runs |
| --- | --- | --- |
| `turn.started` | Temporary thinking/progress line | Full turn metadata |
| `model.token_delta` | Assistant token stream | Model invocation detail |
| `web.search_started` | Compact "Searching web" line | Query, timestamp, provider |
| `web.search_result` | Hidden unless expanded | Results, ranking, receipt |
| `web.read_completed` | Source chip/citation readiness | URL, excerpt, fetched date |
| `tool.proposed` | Actionable proposal card if operator decision needed | Full tool args |
| `tool.stdout_delta` | Concise live output for active command | Full stdout/stderr stream |
| `file.patch_proposed` | Native hunk review | Patch bundle and receipt |
| `policy.approval_required` | Blocking approval dialog/card | Policy evaluation trace |
| `receipt.emitted` | Quiet verified badge only when meaningful | Receipt envelope |
| `trace.step_linked` | View Trace link | Exact focused step |
| `turn.completed` | Final answer; remove temporary spinner | Completed run summary |

### Model Routing

The agentic runtime must use the same Models mode route registry:

- mounted models are selected from daemon-owned route state;
- model route changes are reflected in Studio;
- unavailable/unmounted routes block agent turns with a clear remediation path;
- the model route selector shows mounted routes only by default;
- model-only completions remain available behind explicit mode selection.

### Tool Routing

Tool execution must be daemon-owned:

```text
Studio button/prompt
  -> typed turn/tool request
  -> daemon policy
  -> Rust agentic runtime/tool execution
  -> receipt/event
  -> Studio projection
```

No webview direct execution.
No extension-host durable execution.
No unreceipted mutation.

## Feature Parity Matrix

| Capability | Rust Runtime Target | Current Electron Path | Required Action |
| --- | --- | --- | --- |
| Agent decision loop | multi-step tool-call loop | direct model completion | bridge/default Studio to agent-turn endpoint |
| Web retrieval | `web__search`, `web__read` | not exposed in Studio path | implement first-class web retrieval bridge |
| Current/source questions | retrieval-first rules | stale model prose possible | add intent gate and retrieval-required policy |
| Model streaming | route-backed stream | present | connect same stream to agent turns |
| Tool proposals | typed tool calls | partial UI only | render real `tool.proposed` events |
| Shell commands | `shell__*` lifecycle | `sys.exec` contract only | bridge persistent shell lifecycle and output events |
| File edits | `file__*`, patch lifecycle | coding helper subset | map to native diff/hunk loop with receipts |
| Browser automation | `browser__*` | not in Studio runtime | bridge browser tools or explicit blocker |
| Screen automation | `screen__*` | not in Studio runtime | bridge screen tools or explicit blocker |
| Memory | `memory__*` | not in Studio path | expose memory search/read in agent turns |
| Media evidence | `media__extract_*` | not in Studio path | bridge as trace-only first |
| App launch | `app__launch` | not in Studio path | bridge or block explicitly |
| Software install | resolver/execution plan | not in Studio path | bridge with approval gates |
| Delegation | `agent__delegate` etc. | not in Studio path | bridge worker/subagent events |
| Policy | action targets and escalation | partial JS policy | unify policy event/receipt semantics |
| Tracing | receipts/replay per step | partial | strengthen trace timeline and step refs |

## UX Requirements

### Plain Text Turn

If no tool, file, web, shell, browser, screen, or memory action is used:

- show the user bubble;
- show a small temporary thinking line while waiting;
- stream assistant text;
- remove the thinking line after completion;
- do not show "Worked for X seconds";
- do not show receipt cards;
- do not show verified badges unless a real daemon receipt proves something meaningful.

### Agentic Turn

If tools or runtime actions are used:

- show a compact top-of-answer activity line while active;
- show only user-actionable steps inline;
- collapse exploration details into a document-of-record block when useful;
- link every compact runtime status to Tracing;
- keep full receipts, logs, replay, web source bundles, and policy details in Tracing/Runs.

### Research Turn

For current/source-sensitive questions:

- show "Searching web" or equivalent temporary step;
- show individual search/read steps only while active or if expanded;
- final answer includes citations/source chips;
- Tracing stores queries, source URLs, read excerpts, timestamps, and receipt refs;
- if retrieval is unavailable, Studio must say retrieval is unavailable instead of guessing.

### Coding Turn

For code work:

- show file exploration as a compact document-of-record only when files are actually inspected;
- show command/test output summaries inline;
- show patches through native VS Code diff/hunk UX;
- show hunk accept/reject inline because it is operator-actionable;
- full logs and receipts live in Tracing.

## Implementation Phases

### Phase 0: Inventory And Contract Freeze

Deliverables:

- enumerate Rust agentic tool families and event concepts;
- enumerate JS daemon routes and Studio call paths;
- document the current direct-completion path as Ask/direct-model mode;
- define canonical agent-turn request/response/event schemas;
- define blocker state for missing Rust sidecar availability.

Exit criteria:

- parity matrix committed in this guide;
- target agent-turn API reviewed;
- Studio mode distinction documented.

### Phase 0.5: Fail-Closed Runtime Guard

Deliverables:

- add a source-sensitive prompt detector for latest/current/source/citation/high-stakes prompts;
- add a tool-required prompt detector for repo/code/shell/browser/screen/memory/action prompts;
- add a direct-answer-allowed check derived from CIRC where available;
- add a Studio blocker state for missing Rust runtime bridge;
- add a Studio blocker state for missing web retrieval bridge;
- prevent fallback from Agent Mode to Ask Mode unless the user explicitly chooses Ask.

Exit criteria:

- asking "Is AKT or Filecoin a better investment right now?" cannot return a stale generic model answer when retrieval is unavailable;
- the UI explains which runtime bridge is missing;
- proof JSON reports `agentModeFailsClosedForRetrievalRequiredPrompts: true`.

### Phase 1: Agent Turn Shim

Deliverables:

- add a daemon route for `POST /v1/threads/:thread_id/turns`;
- route Studio Agent Mode through this endpoint;
- keep `/v1/chat/completions` for Ask Mode;
- stream events over SSE or equivalent;
- create trace IDs and receipt refs per turn;
- emit model token deltas as structured events.

Exit criteria:

- Studio no longer calls direct completions in Agent Mode;
- Ask Mode remains explicit and labeled;
- Playwright proves different behavior between modes.

Implementation notes:

- Use the existing `/v1/threads` and `/v1/threads/:thread_id/turns` daemon route shape where possible.
- Create Studio threads with `runtime_profile: runtime_service` in Agent Mode.
- Keep `streamStudioModelCompletion` only for explicit Ask Mode.
- Add static tests that fail if default `submitStudioPrompt` invokes `/v1/chat/completions`.
- If the first bridge returns complete text before event streaming exists, synthetic UI token streaming may be used temporarily only if proof flags clearly mark `realAgentEventStreamingObserved: false`.

### Phase 2: Web Retrieval First

Deliverables:

- bridge `web__search` and `web__read`;
- add retrieval intent gate for current/latest/source/citation/high-stakes questions;
- show active search steps in Studio;
- attach citations/source chips to final answer;
- store source bundles in Tracing;
- block unsupported retrieval with explicit "retrieval unavailable" message.

Exit criteria:

- a current-events query triggers web search;
- an investment/current finance query does not answer from stale model memory;
- citations and absolute dates are present where required;
- Tracing shows exact search/read steps.

Implementation notes:

- Prefer Rust `web__search`/`web__read` semantics over browser SERP automation.
- Preserve search queries, result URLs, selected reads, fetched timestamps, and excerpts in Tracing.
- Add a high-stakes/current facts gate for finance/crypto/investment questions.
- Answers must include a non-advice caveat where appropriate, but the caveat must not replace current evidence gathering.

### Phase 3: Workspace And Coding Tools

Deliverables:

- bridge file read/search/edit primitives;
- bridge shell lifecycle or map JS `sys.exec` into Rust-style shell events;
- add command stdout/stderr streaming;
- add native diff/hunk review;
- add test/diagnostic postcondition events;
- enforce receipt-backed mutation only.

Exit criteria:

- Studio can inspect repo files through agent-turn events;
- Studio can propose a patch without directly mutating from webview;
- hunk accept/reject emits receipts;
- command/test output streams and links to trace.

Implementation notes:

- "Worked for X" appears only when real file/tool/shell/web/browser/screen/memory actions happened.
- Exploration summaries should be document-of-record style, not proof-card walls.
- Plain repo-free answers should remain clean assistant text.

### Phase 4: Browser, Screen, And App Tools

Deliverables:

- bridge browser tools where local browser/CDP is available;
- bridge screen tools where desktop accessibility/screenshot capture is available;
- bridge `app__launch` and verification;
- expose blocker state where host permissions or provider APIs are missing.

Exit criteria:

- browser/screen/app tasks either execute through daemon events or clearly block;
- no fake browser/worker parity;
- screenshots/snapshots are trace-linked.

Implementation notes:

- Browser tools must follow inspect-before-click rules.
- Screen tools must not substitute for browser semantic actions when browser tools are available.
- App launch must verify focus/window state before claiming success.

### Phase 5: Memory, Media, Delegation, And Workers

Deliverables:

- bridge `memory__search` and `memory__read`;
- bridge media evidence extraction;
- bridge agent delegation and worker/subagent lanes;
- connect worker events to Workflow Composer where appropriate.

Exit criteria:

- durable memory queries use memory tools before answering;
- media requests use media extraction where supported;
- worker lanes are visible only when real delegation events exist.

### Phase 6: Policy, Receipts, Replay, And Tracing Completion

Deliverables:

- unify action-target taxonomy between Rust and JS daemon;
- emit policy lease events for elevated actions;
- attach per-step receipts;
- replay any turn from Tracing;
- export proof bundles;
- add truthfulness guardrails that reject model-prose-as-proof.

Exit criteria:

- every consequential action has receipt and trace step;
- denied policy action does not execute;
- Studio compact statuses jump to exact trace steps;
- validation fails when proof is missing.

### Phase 7: Default Runtime Promotion

Deliverables:

- make Agent Mode the default Studio route in normal Autopilot builds;
- make Ask Mode opt-in and visually labeled;
- remove fixture/mock runtime claims from normal Studio;
- keep fixture paths only behind explicit validation/development flags;
- add a product health banner only when the agentic runtime bridge is absent.

Exit criteria:

- a fresh user opening Studio gets the governed agentic runtime path;
- a missing Rust sidecar creates an actionable setup/blocker message, not a fake answer;
- validation cannot pass using fixture-only runtime paths.

## Validation Strategy

Validation must use the real Electron GUI through Playwright/CDP with daemon sidecars attached.

Static tests are necessary but insufficient.

Validation must compare three runtime paths:

1. **Agent Mode with Rust bridge attached**: expected full agentic behavior.
2. **Agent Mode without Rust bridge**: expected fail-closed blockers for runtime-required prompts.
3. **Ask Mode**: expected direct model stream with no execution proof claims.

### Required Prompt Classes

Run at least:

- casual greeting;
- plain explanation with no tool use;
- current web research question;
- source/citation question;
- high-stakes finance/current-market question;
- repo-aware question requiring file inspection;
- code edit proposal requiring hunk review;
- shell/test request;
- browser/screen task or explicit blocker;
- memory/durable context query or explicit blocker;
- malformed/empty prompt;
- stop/resume interaction.

Add these regression prompts specifically because they exposed the product gap:

- "Is AKT or Filecoin a better investment right now?"
- "Compare the latest AKT and Filecoin fundamentals and cite sources."
- "What changed in the repo related to Agent Studio runtime routing?"
- "Search the web for current NIST post-quantum standards and summarize with dates."
- "Read the current workspace files and tell me where Studio submits prompts."
- "Run the relevant static test for ioi-workbench and summarize failures."
- "Open a browser and verify a page title." If browser tools are unavailable, the expected output is a blocker.

### Required Proof Flags

Validation proof JSON must include:

```json
{
  "targetRustAgenticRuntimeParityAchieved": true,
  "studioAgentModeUsesAgentTurnEndpoint": true,
  "studioChatOnlyModeUsesDirectCompletion": true,
  "directCompletionNotAcceptedAsAgenticProof": true,
  "webSearchReadObserved": true,
  "currentFactsRequireRetrieval": true,
  "sourceCitationsObserved": true,
  "modelTokenStreamingObserved": true,
  "toolEventStreamingObserved": true,
  "realAgentEventStreamingObserved": true,
  "agentModeFailsClosedForRetrievalRequiredPrompts": true,
  "agentModeDoesNotFallbackToDirectModelForCurrentFacts": true,
  "rustRuntimeBridgeAttached": true,
  "runtimeBridgeUnavailableBlockerObserved": true,
  "retrievalUnavailableBlockerObserved": true,
  "plainTextTurnHasNoWorkedForCard": true,
  "plainTextTurnHasOnlyTemporaryThinkingLine": true,
  "workRecordOnlyAppearsForToolOrExplorationTurns": true,
  "agenticTurnHasCompactActivityRecord": true,
  "agenticDocumentOfRecordObserved": true,
  "traceLinksOpenExactSteps": true,
  "policyLeaseObserved": true,
  "deniedPolicyActionDidNotExecute": true,
  "filePatchHunkLoopObserved": true,
  "shellOutputStreamObserved": true,
  "receiptsPerConsequentialActionObserved": true,
  "modelProseNotAcceptedAsRuntimeTruth": true,
  "noTauriUsage": true,
  "noWebviewDurableRuntimeAuthority": true,
  "noExternalConnectorAction": true,
  "noOrphanProcesses": true
}
```

If browser/screen/memory/media/delegation are not fully bridged yet, the corresponding proof flags must remain false and the guide must list them as blockers. Do not mark full parity achieved with fake states.

### Required Screenshots

Store evidence under:

```text
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/
```

Required screenshots:

- `agent-mode-selector.png`
- `ask-mode-plain-response-no-work-card.png`
- `agent-mode-current-query-web-search.png`
- `agent-mode-cited-answer.png`
- `agent-mode-tool-proposal.png`
- `agent-mode-shell-output-stream.png`
- `agent-mode-file-patch-native-hunks.png`
- `agent-mode-policy-lease.png`
- `tracing-web-source-bundle.png`
- `tracing-tool-step-receipt.png`
- `tracing-replay-step-detail.png`
- `stop-resume-turn.png`

## Required Scripts

Add:

```text
npm run goal:autopilot-agent-studio-rust-agentic-runtime-parity
npm run goal:autopilot-agent-studio-rust-agentic-runtime-parity:run
```

The validation runner must:

- launch Electron Autopilot;
- launch or attach JS runtime daemon for model mounting;
- launch or attach Rust agentic runtime sidecar;
- verify no stale orphan processes exist before launch;
- drive Studio through Agent Mode and Ask Mode;
- capture screenshots, logs, traces, receipts, and proof JSON;
- clean up all spawned processes;
- update this guide with evidence and blockers.

The runner must fail if it cannot prove the default Agent Mode path uses the agent-turn API. It must not pass simply because the UI rendered an answer.

Minimum runner proof files:

```text
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/proof.json
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/agent-mode-events.jsonl
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/ask-mode-completion-events.jsonl
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/retrieval-sources.json
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/process-cleanup-before-launch.json
docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity/<timestamp>/process-cleanup-after-run.json
```

## Minimum Test Commands

Run at minimum:

```text
npm run goal:autopilot-agent-studio-rust-agentic-runtime-parity
npm run goal:autopilot-agent-studio-rust-agentic-runtime-parity:run
npm run goal:autopilot-agent-studio-runtime-ux-denoising
npm run goal:autopilot-agent-studio-chat-ux-hardening
npm run goal:autopilot-agent-studio-tauri-chat-ux-parity
npm run goal:autopilot-fork-quickinput-parity
node --test apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs
```

Add Rust tests once the bridge endpoint lands:

```text
cargo test -p ioi-services agentic
cargo test -p ioi-types agentic
```

Use the repo's actual crate names if they differ.

## Blockers

Treat any of these as blockers:

- Studio Agent Mode still calls `/v1/chat/completions` directly.
- Current/research/source-sensitive prompts answer without retrieval or explicit retrieval-unavailable disclosure.
- Web search/read tools are absent from the agent-turn tested path.
- Model prose is used as evidence of tool execution.
- Plain text turns show "Worked for X seconds" records.
- Tool/action turns lack structured daemon events.
- Command output does not stream or lacks receipts.
- File mutation occurs without daemon receipt path.
- Native hunk review is missing for patch proposals.
- Policy lease denial still executes the action.
- Trace links do not open exact steps.
- Browser/screen/worker parity is faked instead of blocked.
- Tauri is used or revived.
- Webview or extension host performs durable runtime work directly.
- Validation only proves static code or fixture projections.
- Playwright cannot control the real GUI.
- Screenshots, proof JSON, receipts, or cleanup proof are missing.
- Validation leaves orphan Electron, daemon, model, browser, or Rust runtime processes.

## Completion Gate

Do not mark this guide or the associated `/goal` complete until all are true:

- default Studio Agent Mode uses daemon-owned agent turns;
- Rust runtime bridge is attached in the passing validation path;
- current/source-sensitive prompts trigger retrieval or fail closed;
- `web__search` and `web__read` events are observed in GUI validation;
- direct `/v1/chat/completions` remains available only for explicit Ask Mode;
- plain text answers do not show permanent work/proof UI;
- tool/file/shell/web turns produce compact document-of-record summaries;
- Tracing/Runs holds receipts, sources, logs, replay, and exact trace steps;
- all spawned Electron/daemon/model/browser/Rust processes are cleaned up;
- proof JSON reports `targetRustAgenticRuntimeParityAchieved: true`.

Current readiness state:

```text
Model-backed Studio chat: working.
Rust agentic Studio runtime bridge proof: achieved.
Connector sprint readiness: unblocked for this parity gate; still requires connector-specific policy/approval proof.
```

## Connector Sprint Readiness Impact

Connector sprint readiness requires this parity work because connector actions are consequential.

Before connector sprint entry, Autopilot must prove:

- Studio prompts route through daemon-owned agent turns;
- model route and tool route are both daemon-owned;
- retrieval works for current external facts;
- tool proposals are typed and policy-evaluated;
- approvals block execution;
- receipts and replay are attached to every consequential step;
- direct model prose cannot claim connector success;
- Tracing can reconstruct what happened.

Do not begin real connector-specific sprint work until this is true for local/web/file/shell dry-run actions.

## Recommended Immediate Tactical Cut

Do not try to bridge every Rust feature at once.

The first sprint should be:

1. Add Agent Mode vs Ask Mode distinction.
2. Add agent-turn endpoint shim.
3. Route Studio Agent Mode through agent-turn endpoint.
4. Bridge `web__search` and `web__read`.
5. Enforce retrieval-required gating for current/source/high-stakes prompts.
6. De-noise plain text turns so they do not show run records.
7. Add trace-linked search/read evidence.

This fixes the most visible quality failure first: stale local-model answers where the product should be doing source-grounded agentic work.
