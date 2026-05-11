# Agent Runtime DeepSeek TUI Parity Plus Master Guide

Status: implementation master guide
Audit date: 2026-05-10
Reference implementation: `examples/DeepSeek-TUI-main/DeepSeek-TUI-main`
Canonical IOI boundary references:

- `docs/implementation/runtime-package-boundaries.md`
- `docs/implementation/runtime-module-map.md`
- `docs/architecture/products/autopilot/local-app-workflow-canvas.md`
- `crates/services/src/agentic/runtime/README.md`
- `docs/specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md`

## Executive Goal

Close every practical parity gap between IOI's agent runtime and DeepSeek TUI,
then exceed it without breaking IOI's modular architecture.

Parity means a developer can use IOI as a serious local coding-agent runtime:
terminal-first, resumable, inspectable, live-streaming, tool-rich, safe by
default, and extensible through MCP, skills, hooks, subagents, memory, and
workflow configuration.

Parity plus means every equivalent capability is also:

- backed by IOI's canonical runtime service, tool contracts, receipts, and
  Agentgres-compatible state;
- configurable as a workflow graph in the Autopilot/agent-ide development
  environment;
- observable through replayable events, artifacts, scorecards, rollback proofs,
  and policy receipts;
- exposed consistently through daemon API, SDK, CLI/TUI, and React Flow based
  workflow surfaces;
- governed by wallet.network authority scopes and CIRC primitive capabilities
  rather than a loose tool allowlist.

## Non-Negotiable Doctrine

1. Do not create a second runtime.
2. Do not make the workflow canvas a shadow truth store.
3. Every new capability lands as a runtime component contract first, then a
   daemon projection, then SDK/CLI/TUI/React Flow surfaces.
4. Every visible workflow node must correspond to a canonical component,
   adapter, tool contract, event, or receipt.
5. Every mutable action must produce evidence: event, receipt, artifact, replay
   reference, rollback reference when applicable, and policy decision when
   applicable.
6. Compatibility names from DeepSeek TUI may appear at product/API edges, but
   internal ownership must use IOI's runtime vocabulary.
7. The default harness remains workflow-addressable neutral infrastructure. A
   forked harness is a worker/workflow package, not an implicit mutation of the
   canonical default.

## Current Strengths To Preserve

IOI is already stronger than the reference in several areas:

- policy, approval, and PII enforcement in the runtime service;
- CIRC primitive capability contracts and wallet authority scopes;
- GUI, browser, OS, terminal, MCP, model-router, and memory drivers in one
  runtime service struct;
- harness component contracts, receipts, replay metadata, rollback fields, and
  workflow node readiness;
- local model mounting and governed MCP containment;
- Autopilot as a local/private product surface for workflows, approvals,
  artifacts, receipts, and runtime projection;
- SDK trace, scorecard, artifact, and replay projections.

The work below should not flatten those strengths into a simpler DeepSeek clone.
The target is a coding-agent product surface powered by the stronger IOI
substrate.

## Reference Capability Inventory

DeepSeek TUI provides these user-visible capabilities:

- terminal coding TUI and dispatcher CLI;
- Plan, Agent, and YOLO modes;
- model auto-routing and reasoning effort controls;
- streaming reasoning blocks;
- typed file, shell, git, web, MCP, apply-patch, and subagent tools;
- durable thread, turn, item, and event API;
- live SSE replay and resume by monotonic event sequence;
- session save/resume and task queue survival;
- side-git turn snapshots and restore;
- LSP diagnostics after edits;
- MCP CLI and in-TUI manager;
- subagents with role taxonomy, lifecycle, output contract, and concurrency cap;
- user memory file and `remember` UX;
- cost, usage, cache, and context telemetry;
- doctor/config/introspection commands;
- skills, hooks, localization, and runtime API server modes.

## IOI Gap Categories

Each gap is assigned a close path that covers:

- runtime component;
- daemon/API projection;
- SDK contract;
- CLI/TUI surface;
- React Flow workflow-development surface;
- evidence and tests.

### P0. Live Runtime API Bridge

Problem:

`packages/runtime-daemon` exposes useful agent/run APIs, but current run creation
is synthetic projection logic. It does not tail the live Rust runtime loop as the
canonical source of turn and item state.

Target:

The daemon must submit work into `RuntimeAgentService`, subscribe to canonical
runtime events, persist Agentgres-compatible records, and expose live replayable
streams.

Runtime work:

- Introduce `RuntimeApiBridge` in the canonical runtime layer.
- Convert `KernelEvent`, `AgentState`, `ActionRequest`, tool results, approvals,
  receipts, and harness events into a stable public event envelope.
- Add a runtime-side append-only event writer with monotonic `seq`.
- Persist event cursor, session id, step id, tool call id, approval id, artifact
  ids, rollback ids, and workflow node id when available.

Daemon/API work:

- Add `/v1/threads`, `/v1/threads/{id}`, `/v1/threads/{id}/resume`,
  `/v1/threads/{id}/fork`, `/v1/threads/{id}/turns`,
  `/v1/threads/{id}/turns/{turn_id}/steer`,
  `/v1/threads/{id}/turns/{turn_id}/interrupt`,
  `/v1/threads/{id}/compact`, and
  `/v1/threads/{id}/events?since_seq=N`.
- Keep `/v1/agents` and `/v1/runs` as compatibility aliases over the same
  thread/turn store.
- Move synthetic `buildRun` into an explicit fixture/dev profile. Production
  daemon paths must fail closed if the runtime bridge is unavailable.
- Support `Last-Event-ID` and query cursor replay for SSE.

SDK work:

- Add `Thread`, `Turn`, and `Run` wrappers over the same event stream.
- Keep `Agent.send()` as an ergonomic wrapper around `POST /turns`.
- Add `turn.steer()`, `turn.interrupt()`, `thread.compact()`,
  `thread.fork()`, `thread.events({ sinceSeq })`, and `run.events()`.

CLI/TUI work:

- Add `ioi agent serve` for local daemon startup when needed.
- Add `ioi agent thread list/show/resume/fork/archive`.
- Add `ioi agent send --thread <id>`, `interrupt`, `steer`, `compact`,
  `events`, and `stream`.

React Flow workflow surface:

- Add `RuntimeThreadNode`, `RuntimeTurnNode`, `RuntimeEventStreamNode`,
  `InterruptGateNode`, `SteerInputNode`, and `CompactionNode`.
- Node inspector fields:
  - thread id;
  - turn id;
  - status;
  - latest seq;
  - replay cursor;
  - model route;
  - mode;
  - workspace;
  - policy posture;
  - linked artifacts.
- Edges:
  - `thread -> turn`;
  - `turn -> event_stream`;
  - `turn -> tool_call`;
  - `turn -> approval_gate`;
  - `turn -> artifact`;
  - `turn -> rollback_snapshot`.

Acceptance evidence:

- live turn stream continues after client reconnect;
- replay from `since_seq=0` exactly reconstructs terminal state;
- process restart marks in-flight turns interrupted or resumes via documented
  recovery semantics;
- SDK, CLI, and React Flow read the same event ids;
- fixture mode is visibly labeled and cannot be mistaken for production runtime.

### P0. Durable Thread, Turn, Item Model

Problem:

IOI has `AgentState`, transcript roots, pending-action metadata, and execution
queues, but lacks the public durable lifecycle model that coding-agent clients
expect.

Target:

Expose a durable TTI model without replacing `AgentState`.

Runtime records:

- `RuntimeThreadRecord`
  - `thread_id`;
  - `session_id`;
  - `created_at`;
  - `updated_at`;
  - `workspace`;
  - `title`;
  - `mode`;
  - `approval_mode`;
  - `model_route`;
  - `latest_turn_id`;
  - `latest_seq`;
  - `archived`;
  - `workflow_graph_id`;
  - `harness_binding_id`;
  - `agentgres_projection_ref`.
- `RuntimeTurnRecord`
  - `turn_id`;
  - `thread_id`;
  - `status`;
  - `started_at`;
  - `completed_at`;
  - `usage`;
  - `error`;
  - `stop_reason`;
  - `rollback_snapshot_id`;
  - `quality_ledger_ref`;
  - `workflow_execution_ref`.
- `RuntimeItemRecord`
  - `item_id`;
  - `turn_id`;
  - `kind`;
  - `status`;
  - `seq_start`;
  - `seq_end`;
  - `tool_name`;
  - `component_kind`;
  - `workflow_node_id`;
  - `receipt_refs`;
  - `artifact_refs`;
  - `redaction_profile`.

Item kinds:

- `user_message`;
- `agent_message`;
- `reasoning_delta`;
- `tool_call`;
- `tool_result`;
- `file_change`;
- `command_execution`;
- `approval_required`;
- `approval_decision`;
- `context_compaction`;
- `lsp_diagnostics`;
- `memory_update`;
- `subagent_event`;
- `rollback_snapshot`;
- `status`;
- `error`.

React Flow workflow surface:

- Every item kind has a renderer in the run timeline.
- Every tool-capable item can jump to the graph node that produced it.
- Every graph node can show its emitted items and receipts.
- The bottom shelf should allow filtering by item kind, component kind, status,
  receipt type, and workflow node.

Acceptance evidence:

- old `AgentState` sessions can project into TTI records;
- no event is orphaned from thread and turn ids;
- every item with side effects has at least one receipt or explicit
  no-receipt justification;
- React Flow run replay can rebuild node statuses from events alone.

### P0. Terminal Coding-Agent TUI

Problem:

The current CLI is strong for IOI management and test harnesses, but not a
keyboard-first coding-agent TUI.

Target:

Add a TUI client over the daemon/runtime API, not a private execution loop.

CLI/TUI features:

- `ioi agent tui`;
- `ioi agent --model auto`;
- `ioi agent --mode plan|agent|yolo`;
- `/mode`, `/model`, `/thinking`, `/mcp`, `/memory`, `/jobs`, `/restore`,
  `/compact`, `/cost`, `/doctor`, `/threads`, `/tools`, `/workflow`;
- keyboard mode cycling;
- transcript with reasoning, tool calls, approvals, LSP diagnostics, diffs,
  artifacts, and cost;
- side panel for tasks/jobs/subagents;
- approval modal with policy explanation and receipts;
- restore picker for turn snapshots;
- workflow graph link for every runtime component.

Runtime/API requirements:

- TUI consumes `/v1/threads/*` and event SSE only.
- Approval decisions are submitted via runtime approval API.
- TUI never edits runtime state directly.

React Flow integration:

- Add "Open in Workflow Canvas" from TUI thread/turn/tool/subagent rows.
- Add "Open in TUI" deep link from React Flow node inspector.
- Allow a graph node to be temporarily pinned in the TUI side panel while a turn
  executes.

Acceptance evidence:

- same run can be started from TUI, watched in SDK, and inspected in React Flow;
- interrupt and approval decisions round-trip without event loss;
- terminal close/reopen resumes the same thread by event cursor.

### P0. Coding Tool Pack

Problem:

IOI has broad tool categories, but coding-agent parity needs a focused tool pack
with git, diff, patch, diagnostics, tests, artifact spillover, and job control.

Target:

Create `CodingToolPack` as a modular built-in package over existing runtime tool
contracts.

Tools:

- `file__read`;
- `file__list`;
- `file__search`;
- `file__write`;
- `file__edit`;
- `file__multi_edit`;
- `file__apply_patch`;
- `tool__retrieve_result`;
- `git__status`;
- `git__diff`;
- `git__branch`;
- `git__log`;
- `git__show`;
- `git__restore_preview`;
- `test__run`;
- `diagnostics__workspace`;
- `lsp__diagnostics`;
- `lsp__hover`;
- `lsp__definition`;
- `lsp__references`;
- `shell__run`;
- `shell__start`;
- `shell__status`;
- `shell__input`;
- `shell__terminate`;
- `job__list`;
- `job__wait`;
- `job__cancel`;
- `artifact__create`;
- `artifact__read`;
- `artifact__query`.

Runtime componentization:

- `CodingToolPack` owns registry composition only.
- Filesystem, shell, git, LSP, test runner, artifact store, and job manager stay
  separate components.
- Tool contracts must declare:
  - primitive capabilities;
  - authority scopes;
  - approval behavior;
  - risk class;
  - cancellation behavior;
  - artifact behavior;
  - replayability;
  - redaction.

Daemon/API work:

- Expose coding tool catalog through `/v1/tools?pack=coding`.
- Expose job state through `/v1/jobs` or thread-scoped `/jobs`.
- Expose tool-result artifact slices through `/v1/artifacts/{id}?range=`.

SDK work:

- Generate TypeScript tool-call types from `RuntimeToolContract`.
- Add `agent.tools.list({ pack: "coding" })`.
- Add typed helpers for `run.tests()`, `run.gitDiff()`, and artifact retrieval
  where they remain projections over runtime tool calls.

CLI/TUI work:

- Prefer structured tools over shell in prompts and tool descriptions.
- Add slash commands for `git status`, `diff`, `tests`, `diagnostics`, `jobs`,
  and `artifacts`.

React Flow workflow surface:

- Add configurable tool-pack nodes:
  - `FilesystemToolNode`;
  - `PatchToolNode`;
  - `GitToolNode`;
  - `TestRunnerNode`;
  - `DiagnosticsNode`;
  - `LspNode`;
  - `ShellJobNode`;
  - `ArtifactStoreNode`.
- Node config supports:
  - enabled/disabled;
  - approval profile;
  - path allowlist/denylist;
  - command allowlist;
  - timeout;
  - artifact retention;
  - redaction;
  - concurrency limit.

Acceptance evidence:

- coding task can inspect, patch, test, diagnose, and summarize without shelling
  out for git status/diff;
- large outputs spill to artifacts and are retrievable by slice/query;
- React Flow can disable `shell__run` while keeping git/test tools enabled;
- tool contract snapshots and generated TS types stay in sync.

### P0. Post-Edit LSP Diagnostics

Problem:

DeepSeek TUI injects LSP diagnostics after edits. IOI needs the same loop, plus
workflow-visible diagnostic nodes.

Target:

Implement passive post-edit diagnostics and optional model-callable navigation.

Runtime work:

- Add `LspRuntime` component:
  - server discovery;
  - lazy process lifecycle;
  - per-language configuration;
  - diagnostic collection;
  - timeout handling;
  - crash isolation;
  - workspace trust policy.
- Register post-edit hooks for:
  - `file__write`;
  - `file__edit`;
  - `file__multi_edit`;
  - `file__apply_patch`.
- Emit `lsp.diagnostics.started`, `lsp.diagnostics.completed`,
  `lsp.diagnostics.failed`, and `lsp.diagnostics.injected` events.
- Inject errors before the next model request as compact synthetic context.

Navigation tools:

- `lsp__hover`;
- `lsp__definition`;
- `lsp__references`;
- `lsp__document_symbols`;
- `lsp__workspace_symbols`.

React Flow workflow surface:

- Add `LspDiagnosticsNode` with config:
  - languages;
  - server commands;
  - include warnings;
  - max diagnostics per file;
  - poll delay;
  - inject into prompt;
  - fail-open/fail-closed.
- Add diagnostics overlay in run replay and node inspector.

Acceptance evidence:

- TypeScript/Rust/Python fixture edit emits diagnostics;
- missing LSP binary degrades gracefully;
- diagnostic injection is visible in event stream and prompt audit;
- React Flow can toggle warning injection without code changes.

### P0. Workspace Rollback Snapshots

Problem:

DeepSeek provides side-git turn snapshots and restore. IOI has rollback concepts
but needs coding workspace rollback as a first-class runtime capability.

Target:

Add per-turn workspace snapshots that do not mutate user `.git`.

Runtime work:

- Add `WorkspaceSnapshotService`.
- Snapshot before and after every mutating turn in Agent/YOLO modes.
- Store snapshot metadata:
  - snapshot id;
  - thread id;
  - turn id;
  - workspace root;
  - changed paths;
  - pre hash;
  - post hash;
  - storage path;
  - restore eligibility;
  - receipt refs.
- Support restore preview and restore apply.
- Respect `.gitignore`, path policy, file size limits, and redaction rules.

Daemon/API work:

- `GET /v1/threads/{id}/snapshots`;
- `GET /v1/threads/{id}/snapshots/{snapshot_id}/diff`;
- `POST /v1/threads/{id}/snapshots/{snapshot_id}/restore-preview`;
- `POST /v1/threads/{id}/snapshots/{snapshot_id}/restore`.

CLI/TUI work:

- `/restore`;
- `/restore preview <turn>`;
- `ioi agent restore --thread <id> --turn <turn_id>`.

React Flow workflow surface:

- Add `RollbackSnapshotNode` and `RestoreGateNode`.
- Show snapshot badges on mutating tool nodes.
- Allow graph-level policy:
  - snapshot every mutating turn;
  - snapshot only high-risk tools;
  - no snapshots;
  - restore requires approval.

Acceptance evidence:

- restore changes workspace files without touching user `.git`;
- restore emits receipt and event sequence;
- restore is replayable in timeline;
- React Flow restore gate blocks automated restore unless configured.

### P1. Subagent Runtime Parity

Problem:

IOI has delegation and worker templates, but lacks the full productized subagent
API and lifecycle expected by coding agents.

Target:

Add a role-aware subagent manager over IOI's worker/delegation substrate.

Tools/API:

- `agent_spawn`;
- `agent_wait`;
- `agent_result`;
- `agent_send_input`;
- `agent_cancel`;
- `agent_list`;
- `agent_resume`;
- `agent_assign`.

Role taxonomy:

- `general`;
- `explore`;
- `plan`;
- `review`;
- `implementer`;
- `verifier`;
- `custom`.

IOI plus taxonomy:

- `browser_operator`;
- `gui_operator`;
- `security_reviewer`;
- `policy_reviewer`;
- `workflow_designer`;
- `connector_author`;
- `model_router`;
- `receipt_auditor`.

Runtime work:

- Add `SubagentManager` as a component over current delegation lifecycle.
- Support fresh child context by default.
- Support `fork_context: true` with stable prompt-prefix reuse.
- Stamp each subagent with:
  - `agent_id`;
  - `parent_thread_id`;
  - `parent_turn_id`;
  - `role`;
  - `tool_pack`;
  - `workflow_node_id`;
  - `session_boot_id`;
  - lifecycle status;
  - output contract status.
- Enforce concurrency caps by role and cost class.

Output contract:

- `SUMMARY`;
- `CHANGES`;
- `EVIDENCE`;
- `RISKS`;
- `BLOCKERS`;
- `RECEIPTS`.

React Flow workflow surface:

- Add `SubagentPoolNode`, `SubagentRoleNode`, `SubagentSpawnNode`,
  `SubagentJoinNode`, and `SubagentResultNode`.
- Configurable fields:
  - role;
  - model route;
  - tool pack;
  - fresh/forked context;
  - max concurrency;
  - budget;
  - output contract;
  - merge policy;
  - cancellation inheritance.
- Show subagent children as collapsible graph subflows.

Acceptance evidence:

- parent can spawn explorer and implementer in parallel;
- cancellation propagates to descendants;
- subagent restart status is explicit;
- React Flow max-concurrency setting changes runtime behavior;
- output contract is validated before parent merge.

### P1. MCP Manager Parity

Problem:

IOI has MCP containment and CLI inspection, but needs the polished manager
experience and self-hosted MCP server modes.

Target:

Make MCP discoverable, configurable, inspectable, and workflow-addressable.

CLI/API:

- `ioi mcp init`;
- `ioi mcp list`;
- `ioi mcp tools`;
- `ioi mcp add`;
- `ioi mcp enable`;
- `ioi mcp disable`;
- `ioi mcp remove`;
- `ioi mcp validate`;
- `ioi mcp invoke`;
- `ioi mcp serve`;
- `ioi agent /mcp`.

Runtime work:

- Preserve `McpManager` as execution owner.
- Add config resolver for:
  - IOI workload config;
  - `.cursor/mcp.json`;
  - `.agents/mcp.json`;
  - global IOI config.
- Generate tool names with stable namespacing.
- Add MCP resource and prompt helper tools.
- Add tool-search/deferred exposure for large MCP servers.

React Flow workflow surface:

- Add `McpServerNode`, `McpToolNode`, `McpResourceNode`, and
  `McpContainmentNode`.
- Configurable fields:
  - transport;
  - command/url;
  - env vault refs;
  - containment mode;
  - tool allowlist;
  - network egress;
  - child process permission;
  - resource exposure;
  - prompt exposure;
  - approval mode.

Acceptance evidence:

- imported `.cursor/mcp.json` creates governed MCP config without bypassing IOI
  containment;
- MCP tools can be disabled in React Flow and disappear from runtime tool
  discovery;
- side-effectful MCP calls require approval outside YOLO/trusted policy;
- self-hosted MCP server exposes IOI tools to another MCP client.

### P1. Modes, Approval, And Trust Profiles

Problem:

DeepSeek exposes Plan, Agent, and YOLO. IOI has richer policy internals but needs
clear product-level modes.

Target:

Map simple user modes to IOI's componentized safety model.

Modes:

- `plan`
  - read-only;
  - no file writes;
  - no shell mutations;
  - no external side effects;
  - workflow edits are proposal-only.
- `agent`
  - bounded tool use;
  - approvals for mutations and authority scopes;
  - default coding-agent mode.
- `yolo`
  - trusted workspace only;
  - auto-approve bounded local tools;
  - authority scopes still require wallet/network policy unless explicitly
    leased.
- `review`
  - read-only plus diagnostics/test execution when safe;
  - no mutation.
- `workflow_design`
  - can propose graph changes;
  - cannot activate without validation.

Runtime work:

- Extend `AgentMode` or introduce `RuntimeInteractionMode`.
- Add `ApprovalMode`:
  - `suggest`;
  - `auto_local`;
  - `never_prompt`;
  - `human_required`;
  - `policy_required`.
- Add workspace trust record.

React Flow workflow surface:

- Add graph-level mode selector.
- Add node-level approval override where policy permits.
- Add visual warnings for YOLO/trusted workspace activation.
- Add "proposal-only" lock state for workflow edits.

Acceptance evidence:

- Plan mode blocks mutating tools at runtime even if a UI enables them;
- YOLO cannot bypass wallet authority scopes;
- mode changes are evented, persisted, and replayable;
- React Flow graph export includes mode and approval profile.

### P1. Cost, Usage, Context, And Capacity Telemetry

Problem:

IOI tracks tokens and budgets, but users need product-grade usage telemetry.

Target:

Expose live per-turn/session usage, cost estimates, context pressure, cache
signals, and capacity routing decisions.

Runtime work:

- Normalize provider usage:
  - input tokens;
  - output tokens;
  - reasoning tokens;
  - cached input tokens;
  - tool result tokens;
  - compacted tokens;
  - estimated cost;
  - model route;
  - provider;
  - latency.
- Emit `usage.delta`, `usage.final`, `context.pressure`, and
  `compaction.recommended`.

Daemon/API:

- `GET /v1/usage?since=&until=&group_by=day|model|provider|thread|workflow`;
- `GET /v1/threads/{id}/usage`;
- include usage on `TurnRecord`.

SDK:

- `run.usage()`;
- `thread.usage()`;
- `client.usage.list()`.

CLI/TUI:

- `/cost`;
- `/context`;
- live footer with turn/session usage.

React Flow workflow surface:

- Add `UsageMeterNode`, `ContextBudgetNode`, and `CompactionPolicyNode`.
- Show cost and latency on model/tool/subagent nodes.
- Allow workflow-level budget caps:
  - max cost;
  - max turns;
  - max tool calls;
  - max subagents;
  - max output tokens.

Acceptance evidence:

- usage endpoint aggregates across local daemon runs;
- model-route changes are visible with rationale;
- workflow budget cap stops execution with a receipt;
- React Flow can simulate cost before activation when estimates exist.

### P1. Model Auto-Routing And Reasoning Effort

Problem:

DeepSeek has user-visible auto model and thinking controls. IOI has model
routing pieces but needs a cohesive coding-agent route surface.

Target:

Expose routing as a first-class runtime component and workflow node.

Runtime work:

- Add `ModelRouteDecision` event with:
  - selected model;
  - provider;
  - reasoning effort;
  - local/remote placement;
  - privacy posture;
  - cost estimate;
  - fallback model;
  - rationale;
  - policy constraints.
- Add `model=auto` resolver that never sends `"auto"` upstream.
- Retain provider-specific reasoning fields in transcript audit when available.

React Flow workflow surface:

- Add `ModelRouterNode`.
- Configurable fields:
  - model policy;
  - provider priority;
  - local-only;
  - remote allowed;
  - reasoning effort;
  - max cost;
  - fallback;
  - privacy tier;
  - capability tags.

Acceptance evidence:

- auto route decision is visible in TUI and graph;
- failed router call falls back deterministically;
- route decision has receipt/evidence;
- workflow config can pin model or choose auto.

Implementation slice completed 2026-05-11:

- `ModelRouteDecision` now projects through daemon thread, turn, run trace, and
  TTI event envelopes as a first-class `model_route_decision` item.
- Agent creation and per-run model overrides resolve through the modular model
  mounting router, preserving React Flow workflow graph/node ids in the route
  decision.
- `model=auto` resolves before provider invocation and deterministic fallback to
  `route.local-first` emits `fallbackTriggered`, rejected candidates, and a
  route receipt.
- SDK types expose `ModelRouteDecision`, `RuntimeTraceBundle.modelRouteDecision`,
  `IOIRunResult.routeDecision`, and `Run.routeDecision()`.
- CLI contract scaffolding exposes `agent model --json` and
  `agent thinking --json` for `/model`, `/thinking`, and React Flow
  `Model Router` configuration parity.

Validation evidence:

- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json`

### P1. Memory UX

Problem:

IOI has richer memory internals, but lacks the simple user-facing memory UX that
DeepSeek users expect.

Target:

Add simple, explicit memory operations over the governed memory runtime.

User surfaces:

- `# remember ...`;
- `/memory`;
- `/memory show`;
- `/memory edit`;
- `/memory disable`;
- `/memory path`;
- `remember` tool.

Runtime work:

- Memory writes emit receipt and redaction metadata.
- Memory can be scoped:
  - global;
  - workspace;
  - thread;
  - workflow;
  - subagent role.
- Prompt injection includes memory block with stable prefix where possible.

React Flow workflow surface:

- Add `MemoryScopeNode`, `RememberNode`, `MemorySearchNode`, and
  `MemoryInjectionNode`.
- Workflow config controls:
  - memory scope;
  - injection enabled;
  - read-only memory;
  - write requires approval;
  - retention;
  - redaction.

Acceptance evidence:

- remembered fact appears in next turn with memory provenance;
- memory writes are visible in receipts;
- workflow can run with memory disabled;
- subagent memory inheritance is explicit.

Implementation slice completed 2026-05-11:

- Runtime daemon now has a durable `AgentMemoryStore` with governed records under
  the daemon state directory, explicit `# remember ...` writes, `/memory` and
  `/memory show` reads, thread/agent memory endpoints, and `memory_update` TTI
  events with `MemoryWrite` payloads.
- Memory writes project into run receipts, trace bundles, turn projections,
  evidence refs, task-state known facts, and workflow-addressable runtime nodes
  so a later turn can explain which memory fact was injected.
- SDK exposes `Agent.memory.remember()`, `Agent.memory.list()`,
  `SendOptions.memory.remember`, `SendOptions.memory.disabled`,
  `AgentMemoryRecord`, and memory-aware mock runtime behavior for local
  workflow tests.
- CLI exposes `ioi agent memory --json` as the operator/workflow contract for
  `# remember`, `/memory`, memory endpoints, `memory_update`, and React Flow
  memory configuration fields.
- Contract tests now assert memory write/injection provenance through the live
  daemon, SDK mock runtime, CLI parser surface, and React Flow workflow
  contract files.

Remaining memory UX closure:

- Closed by the 2026-05-11 subagent memory inheritance execution slice below.

Implementation slice completed 2026-05-11, memory policy controls:

- Runtime memory now persists policy records alongside memory records, with
  effective thread policy projection, storage path projection, and
  `memory_policy` receipts.
- Slash/runtime commands now cover `/memory disable`, `/memory enable`,
  `/memory path`, `/memory edit <id> <text>`, and `/memory delete <id>`.
- Thread and agent memory APIs now expose `memory/policy`, `memory/path`, and
  record `PATCH`/`DELETE` endpoints.
- Runtime policy enforcement blocks writes when memory is disabled, read-only,
  or waiting on explicit write approval, while still allowing read/path/policy
  commands.
- `memory_update` now carries `MemoryWrite`, `MemoryEdit`, `MemoryDelete`, and
  `MemoryPolicy` event kinds, receipt refs, policy IDs, and workflow node IDs.
- SDK helpers now expose `Agent.memory.edit()`, `delete()`, `policy()`,
  `configure()`, and `path()`, plus typed policy/path/update inputs.
- React Flow workflow editor and node registry now expose memory injection,
  read-only memory, write approval, and subagent inheritance controls on model
  nodes, and parity contracts require memory policy/edit/path nodes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json`

Implementation slice completed 2026-05-11, workflow memory execution wiring:

- React Flow model nodes now expose a concrete memory scope selector alongside
  key, injection, read-only, write approval, and subagent inheritance controls.
- Local workflow execution projects model-node memory policy into
  `runtimeSendOptions.memory` and `attachments.memoryPolicy`, so workflow run
  evidence shows the exact memory send options used by the node.
- Daemon workflow-node execution normalizes direct, nested `logic`, and nested
  `memory` fields into `SendOptions.memory`, records them on model invocation
  receipts, and returns them through the native workflow invocation response.
- Workflow memory writes now fail closed before provider invocation when memory
  is disabled, read-only, or requires approval without an approval bit.
- The model-mounting facade stayed under its extraction guard by moving
  workflow-node response shaping and workflow-memory normalization into focused
  modules under `packages/runtime-daemon/src/model-mounting/`.

Validation evidence:

- `node --check packages/runtime-daemon/src/model-mounting.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-memory.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-node.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-17-06-563Z/result.json`

Implementation slice completed 2026-05-11, workflow memory search/list:

- Thread and agent memory projections now accept `scope`, `memoryKey`,
  `q/query`, `limit`, and `redaction` filters, and returned projections include
  the normalized filter contract plus `totalMatches`.
- Memory records now carry optional `memoryKey` metadata so workflow-level state
  keys can address durable memory without relying on ad hoc text matching.
- SDK memory helpers now expose typed filtered `list()` options and
  `Agent.memory.search(query, options)`, with matching behavior in the mock
  substrate and daemon HTTP client.
- React Flow state nodes now expose `memory_search` and `memory_list`
  operations with scope, key, query, limit, and redaction controls; creator
  variants `memory.search` and `memory.list` produce model-ready memory
  attachments.
- Local workflow execution filters incoming memory records, applies optional
  redaction, emits `memoryQuery` evidence, and feeds the filtered state
  attachment into model nodes through the existing memory port.
- Harness component contracts now include `memory_search` and `memory_list`
  alongside read/write/policy memory components.

Validation evidence:

- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json`

Implementation slice completed 2026-05-11, subagent memory inheritance execution:

- SDK `AgentSubagent.send()` handoffs now emit a typed
  `SubagentMemoryInheritanceProjection` on `RuntimeTraceBundle`, with parent
  policy, effective subagent policy, normalized memory filters, inherited
  record IDs, write allowance, and write block reason.
- The live daemon mirrors the same handoff contract through thread turns and
  run traces, including `subagent_memory_inheritance` receipts and
  `memory_update` events with `SubagentMemoryInheritance` payloads.
- Inheritance modes are enforced before subagent writes:
  - `none` disables inherited memory and blocks parent-memory writes;
  - `explicit` only exposes records selected by explicit memory filters and
    requires write approval;
  - `read_only` exposes inherited records while blocking writes;
  - `full` exposes inherited records and preserves the parent write policy.
- React Flow workflow contracts now include `memory.subagentInheritance`, and
  the harness component registry exposes a `memory_subagent_inheritance`
  component so workflow authors can model the inheritance policy as a first
  class state/policy component.
- Contract tests assert filtered record visibility, write blocking, full-write
  persistence, receipts, events, and TTI payload summaries across SDK mock and
  live daemon execution.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json`

### P1. Doctor, Config, And Introspection

Problem:

DeepSeek exposes `doctor --json` and clear config readiness. IOI has several
inspection commands, but needs one canonical health report.

Target:

Add `ioi agent doctor --json` as a comprehensive runtime readiness endpoint.

Report fields:

- version;
- daemon endpoint;
- runtime bridge status;
- workspace;
- config paths;
- provider keys by source, never value;
- model routes;
- MCP config and server health;
- skills/hooks directories;
- memory status;
- LSP status;
- sandbox status;
- side snapshot status;
- artifact/spillover status;
- tool pack status;
- workflow graph schema version;
- React Flow registry version;
- Agentgres store status;
- wallet/network approval status.

Daemon/API:

- `GET /v1/doctor`.

React Flow workflow surface:

- Add `RuntimeDoctorNode`.
- Workflow activation checklist consumes the same doctor report.
- Graph nodes with failing dependencies show readiness blockers.

Acceptance evidence:

- doctor returns JSON in clean and degraded environments;
- activation is blocked by failed required dependencies;
- optional dependencies degrade without false failure;
- no secrets are printed.

Implementation slice completed 2026-05-11, runtime doctor preflight:

- The live daemon now exposes `GET /v1/doctor` with
  `ioi.agent-runtime.doctor.v1`, required readiness checks, optional degraded
  checks, provider key presence, model routes, MCP, memory, sandbox, workflow,
  Agentgres, wallet/network, runtime node, blocker, and redaction metadata.
- `ioi agent doctor --json` now prefers the daemon report and falls back to a
  local static contract report when the daemon is unreachable, preserving
  redaction and never printing provider values.
- React Flow now includes a `runtime_doctor` / `RuntimeDoctorNode` palette
  entry with typed report and blocker outputs, activation-gate defaults, schema
  discovery, canvas labels, and harness component wiring through state and
  verifier policy slots.
- Contract tests assert clean/degraded doctor JSON, required dependency pass
  semantics, optional warnings, hashed endpoint/provider values, CLI command
  parsing, and workflow-addressable doctor node wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json`

### P1. Skills And Hooks

Problem:

DeepSeek packages skills and hooks as user-extensible surfaces. IOI needs
compatible discovery while preserving governance.

Target:

Make skills and hooks runtime components that are graph-configurable.

Skills:

- discover from:
  - workspace IOI skills;
  - `.agents/skills`;
  - `.cursor/skills`;
  - `.claude/skills`;
  - global IOI skill dirs.
- validate `SKILL.md` and frontmatter.
- hash and record active skill set per turn.
- expose skill provenance in prompt audit.

Hooks:

- pre-model hook;
- post-model hook;
- pre-tool hook;
- post-tool hook;
- approval hook;
- event subscriber hook;
- workflow activation hook.

React Flow workflow surface:

- Add `SkillNode`, `SkillPackNode`, `HookNode`, and `HookPolicyNode`.
- Hooks can subscribe to event kinds.
- Hook side effects must declare tool contracts and authority scopes.

Acceptance evidence:

- Cursor-style skill imports are accepted as governed skills;
- hook failure policy is configurable;
- active skill/hook set is visible in TUI and graph;
- hooks cannot mutate runtime outside declared capabilities.

Implementation slice completed 2026-05-11, read-only skill and hook discovery:

- The daemon now exposes `GET /v1/skills` and `GET /v1/hooks` with governed,
  read-only projections for workspace IOI, `.agents`, `.cursor`, `.claude`,
  and global IOI/Agents discovery sources.
- Cursor-style `SKILL.md` imports are normalized with provenance, trust level,
  capability scopes, validation status, skill hashes, and active skill-set hash.
- Hook discovery reads hook JSON files/directories, exposes event subscriptions,
  configurable failure policy, authority scopes, tool contract declarations, and
  a mutation policy that blocks work outside declared capabilities.
- Hook command bodies are never returned; the registry only reports command
  presence and a hash for audit/debugging.
- `GET /v1/doctor` now derives the `skills.hooks` check from the daemon-owned
  catalog instead of a static degraded placeholder.
- `ioi agent skills --json` and `ioi agent hooks --json` expose the same daemon
  projections for TUI/CLI inspection, with degraded local fallbacks when the
  daemon is unreachable.
- React Flow now has `SkillNode`, `SkillPackNode`, `HookNode`, and
  `HookPolicyNode` registry entries plus harness components for skill and hook
  registry discovery.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json`

Implementation slice completed 2026-05-11, active skill/hook manifest per turn:

- Each daemon run/turn now records an
  `ioi.agent-runtime.active-skill-hook-manifest.v1` snapshot with selected
  skill IDs, hook IDs, active skill/hook set hashes, catalog hashes,
  provenance, validation status, and redaction metadata.
- The run trace includes the active manifest and a prompt audit record that
  links prompt hash, selected skill IDs, selected hook IDs, active set hashes,
  and hook execution state without returning skill bodies or hook commands.
- The TTI event stream emits an `ActiveSkillHookManifest` item with receipt
  refs, artifact refs, selected skill/hook counts, and mutation-blocked hook
  counts, preserving replayable provenance before any hook can execute.
- The run artifact list now includes `active-skill-hook-manifest.json`, and the
  trace receipts include an `active_skill_hook_manifest` receipt.
- Hook execution remains disabled; command-backed hooks are marked mutation
  blocked unless they declare both authority scopes and tool contracts.
- React Flow `SkillNode`, `SkillPackNode`, `HookNode`, and `HookPolicyNode`
  defaults now declare activation gates that consume the active skill/hook
  manifest and validate active skill/hook set hashes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json`

Implementation slice completed 2026-05-11, hook dry-run policy preview:

- Each run now derives an `ioi.agent-runtime.hook-dry-run-plan.v1` from the
  active skill/hook manifest before any hook can execute.
- Command-backed hooks are classified as `would_run` only when they declare
  both authority scopes and tool contracts; otherwise they are `blocked`.
  Hooks without commands are `skipped`.
- The dry-run plan is explicitly preview-only: `hookExecutionEnabled` and
  `commandExecutionEnabled` remain false, and every decision records
  `commandExecuted: false`.
- The trace now includes `hookDryRunPlan`, the prompt audit references its plan
  ID, receipts include `hook_dry_run_plan` and `hook_policy_decision`, and the
  artifact list includes `hook-dry-run-plan.json`.
- The TTI event stream emits a `HookDryRunPlan` item on `runtime.hook-policy`
  with decision counts, policy status, receipt refs, and artifact refs.
- React Flow now treats hook policy as its own workflow-addressable harness
  component and `HookPolicyNode` default logic consumes the hook dry-run plan
  and policy decision fields.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json`

Implementation slice completed 2026-05-11, HookPolicyNode activation gate:

- `HookPolicyNode` is now an enforced activation gate, not only descriptive
  metadata. Workflow readiness inspects hook policy nodes and blocks activation
  when their dry-run policy decision is `blocked`.
- Hook policy nodes must remain preview-only: activation fails if node logic or
  the dry-run plan enables hook execution or command execution.
- Hook policy nodes must consume `hookDryRunPlan`, expose the policy decision
  field, and configure explicit passed-preview and blocked routes.
- The default agent harness now includes a benign empty hook dry-run plan for
  its `hook_policy` component, so the blessed harness remains inspectable while
  forks and custom workflows can surface real hook blockers.
- The harness activation test coverage now proves a blocked dry-run plan marks
  the hook policy node as blocked, while a passed preview plan does not add a
  hook policy blocker.

Validation evidence:

- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json`

Implementation slice completed 2026-05-11, hook invocation ledger:

- Each run now derives an `ioi.agent-runtime.hook-invocation-ledger.v1` from
  emitted lifecycle event kinds and the active hook dry-run plan.
- The ledger records preview `HookInvocationRecord` entries for matching hook
  subscriptions such as `workflow_activation`, `pre_model`, and `post_model`.
- Invocation records link the run ID, manifest ID, dry-run plan ID, lifecycle
  event kind, hook ID, hook definition hash, policy decision, blockers,
  workflow node ID, and execution proof.
- Invocation states mirror the dry-run policy as `would_run`, `blocked`, or
  `skipped`; every record remains preview-only with `commandExecuted: false`.
- The TTI event stream emits `HookInvocationLedger` on
  `runtime.hook-invocations`, and artifacts now include
  `hook-invocations.json`.
- React Flow `HookNode` metadata now exposes `hookInvocationLedger` and
  invocation state fields so event subscription and invocation state are
  workflow-addressable while `HookPolicyNode` remains the activation gate.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json`

Implementation slice completed 2026-05-11, hook escalation receipts:

- Blocked hook preview invocations now produce deterministic
  `HookEscalationReceipt` evidence instead of only appearing as blocked ledger
  rows.
- Escalation records preserve the blocked invocation ID, hook ID, event kind,
  failure policy, blockers, missing declarations, recommended next action, and
  non-execution proof.
- Missing hook declarations are reported as first-class receipt details:
  `authorityScopes` and/or `toolContracts`, with explicit safe placeholders
  for the declaration fixes required before execution can be requested.
- The hook invocation ledger now exposes `escalationCount` and `escalations`,
  and the TTI `HookInvocationLedger` event links both the ledger receipt and
  any escalation receipt IDs.
- Receipts, semantic impact, prompt audit, postconditions, and minimum evidence
  now include the escalation path when blocked hook invocations exist.
- React Flow `HookPolicyNode` metadata now exposes escalation count, details,
  and receipt fields so workflow authors can route or display blocked-hook
  remediation inside the agentic workflow creator.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json`

### P2. GitHub And PR Workflow Parity Plus

Problem:

DeepSeek has GitHub context and PR attempts in its durable task model. IOI needs
this for hosted/worker coding parity.

Target:

Add governed repo/PR workflow components.

Runtime components:

- `RepositoryContextService`;
- `GitHubContextService`;
- `PrAttemptService`;
- `BranchPolicyService`.

Tools/API:

- `github__context`;
- `github__issue_read`;
- `github__pr_read`;
- `github__pr_create`;
- `github__pr_update`;
- `github__comment`;
- `github__checks`.

React Flow workflow surface:

- Add `RepositoryNode`, `IssueNode`, `PrAttemptNode`, `BranchPolicyNode`,
  `ReviewGateNode`.

Acceptance evidence:

- PR creation requires authority scope;
- branch and diff are attached to artifacts;
- failed PR attempt is recorded without losing run state;
- workflow graph can require review before PR creation.

Implementation slice completed 2026-05-11, repository context foundation:

- Added a read-only `ioi.agent-runtime.repository-context.v1` projection for
  local Git/workspace state, exposed through `/v1/repository-context` and the
  existing `/v1/repositories` catalog.
- Repository context now captures repo root, workspace-relative path, branch,
  detached-HEAD state, HEAD SHA, upstream, remotes, ahead/behind counts, dirty
  status, staged/unstaged/untracked/conflicted counts, and redacted remote URL
  hashes.
- Each run now records repository context in task facts, postconditions,
  minimum evidence, semantic impact, prompt audit, receipts, trace, artifacts,
  and TTI events.
- The `RepositoryContext` TTI event is workflow-addressable at
  `runtime.repository-context`, with receipt refs and
  `repository-context.json` artifact refs.
- React Flow now has a `repository_context` / `RepositoryContextNode` contract
  with branch, HEAD, dirty-state, endpoint, read-only, and redaction fields.
- The default harness now includes a repository context component so later
  branch policy, review, GitHub, and PR workflow nodes consume canonical repo
  state instead of rediscovering it ad hoc.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json`

Implementation slice completed 2026-05-11, branch policy gate:

- Added a read-only `ioi.agent-runtime.branch-policy.v1` decision that
  consumes canonical `RepositoryContext` before any branch mutation or PR path.
- Branch policy now evaluates Git availability, named branch vs detached HEAD,
  protected/default branch status, HEAD, upstream, ahead/behind, dirty state,
  untracked files, and conflicted worktree counts.
- Decisions are deterministic as `passed`, `warning`, or `blocked`, and expose
  blockers, warnings, review requirements, approval requirements,
  `mutationAllowed`, and `prCreationAllowed`.
- Each run now records branch policy in task facts, postconditions, minimum
  evidence, semantic impact, prompt audit, receipts, trace, artifacts, and TTI
  events.
- The `BranchPolicyDecision` TTI event is workflow-addressable at
  `runtime.branch-policy`, with receipt refs and `branch-policy.json` artifact
  refs.
- React Flow now has a `branch_policy` / `BranchPolicyNode` contract that
  consumes repository context and exposes branch policy status, blockers,
  warnings, receipt refs, and protected-branch configuration.
- The default harness now routes `branch_policy` immediately after
  `repository_context`, making later PR, review, and GitHub workflow nodes
  consume a canonical branch gate.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json`

Implementation slice completed 2026-05-11, GitHub context projection:

- Added a read-only `ioi.agent-runtime.github-context.v1` projection that
  consumes canonical `RepositoryContext` and `BranchPolicyDecision` before any
  PR workflow can claim GitHub readiness.
- GitHub context now detects GitHub remotes from redacted local Git remote
  metadata, exposes owner, repo, repo full name, HTML URL, branch/default branch,
  branch-policy status, blockers, warnings, and PR creation preconditions.
- Credential handling records only token source availability (`GITHUB_TOKEN` or
  `GH_TOKEN`) and never stores token values, authorization headers, network
  responses, or remote credentials.
- Each run now records GitHub context in task facts, postconditions, minimum
  evidence, semantic impact, prompt audit, receipts, trace, artifacts, and TTI
  events.
- The `/v1/github-context` endpoint and `GitHubContext` TTI event are explicitly
  read-only: no network lookup, no PR mutation, and no credential disclosure.
- React Flow now has a `github_context` / `GitHubContextNode` contract that
  consumes repository context and branch policy, and exposes GitHub remote
  identity plus PR preconditions for workflow routing.
- The default harness now routes `github_context` immediately after
  `branch_policy`, so later issue, review, and PR attempt workflow nodes can
  depend on canonical GitHub readiness instead of re-parsing remotes.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json`

Implementation slice completed 2026-05-11, PR attempt preview ledger:

- Added a preview-only `ioi.agent-runtime.pr-attempt.v1` record that consumes
  canonical repository context, branch policy, and GitHub context before any PR
  creation path can proceed.
- The PR attempt ledger records target repo, branch/default branch, HEAD SHA,
  branch-policy blockers/warnings, GitHub PR preconditions, required authority
  scope (`github.pr.create`), missing authority scope, and failure outcome
  without losing run state.
- PR attempts are explicitly non-mutating: `previewOnly: true`,
  `mutationAttempted: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Each run now emits `PrAttemptRecord` on `runtime.pr-attempt`, with receipt
  refs and artifact refs for `pr-attempt.json`, `pr-branch.json`, and
  `pr-diff.patch`.
- Diff content is attached only as the patch artifact; the trace/projection keeps
  diff metadata and hashes so workflow nodes can route on the attempt without
  inflating the state payload.
- React Flow now has a `pr_attempt` / `PrAttemptNode` contract that consumes
  repository context, branch policy, and GitHub context, and exposes status,
  blockers, authority, branch artifact, diff artifact, and receipt fields.
- The default harness now routes `pr_attempt` immediately after
  `github_context`, giving later review-gate and PR-create nodes a durable,
  auditable precondition record to consume.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json`

Implementation slice completed 2026-05-11, review gate decision:

- Added a read-only `ioi.agent-runtime.review-gate.v1` decision that consumes
  repository context, branch policy, GitHub context, and the preview-only PR
  attempt before any PR creation path can proceed.
- Review gate now records required reviewers, required checks, PR attempt ID,
  branch/repo target, blockers, warnings, approval requirements, review
  satisfaction state, and PR creation allowance.
- The gate currently fails closed when the PR attempt is blocked or human review
  is unsatisfied, preserving `mutationAllowed: false`,
  `prCreationAllowed: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Each run now emits `ReviewGateDecision` on `runtime.review-gate`, with receipt
  refs and a `review-gate.json` artifact.
- React Flow now has a `review_gate` / `ReviewGateNode` contract that consumes
  repository context, branch policy, GitHub context, and PR attempt, and exposes
  review status, blockers, reviewers, checks, and receipt fields.
- The default harness now routes `review_gate` immediately after `pr_attempt`,
  satisfying the parity requirement that workflow graphs can require review
  before PR creation.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json`

Implementation slice completed 2026-05-11, issue context projection:

- Added a read-only `ioi.agent-runtime.issue-context.v1` projection that binds
  optional GitHub issue/task context into the PR workflow lane.
- Issue context supports a durable `unbound` state when no issue is supplied,
  allowing local PR previews to continue while preserving a canonical slot for
  future `github__issue_read` results.
- The projection records provider/repo identity, optional issue number/title/URL,
  linked PR attempt ID, linked review gate ID, no-issue policy, warnings,
  redaction posture, and no-network/no-mutation proof.
- Each run now emits `IssueContext` on `runtime.issue-context`, with receipt refs
  and an `issue-context.json` artifact.
- React Flow now has an `issue_context` / `IssueContextNode` contract that
  consumes GitHub context and exposes issue bound state, status, issue number,
  source URL, and receipt fields.
- `pr_attempt` and `review_gate` now expose optional `issue_context` side-input
  ports, while the default harness routes `issue_context` between
  `github_context` and `pr_attempt`.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json`

Implementation slice completed 2026-05-11, GitHub PR create dry-run plan:

- Added a dry-run-only `ioi.agent-runtime.github-pr-create-plan.v1` projection
  that consumes repository context, branch policy, GitHub context, issue
  context, PR attempt, and review gate before any GitHub PR creation tool can
  claim readiness.
- The plan records target owner/repo, base/head branches, title, body plan,
  issue link, review status, request payload hash, authority scope requirements,
  blockers, warnings, and redaction posture.
- PR creation remains explicitly non-mutating:
  `dryRun: true`, `mutationAttempted: false`, `mutationExecuted: false`, and
  `networkLookupPerformed: false`.
- Request evidence is safe by construction: the projection stores a payload
  hash and non-secret preview metadata, while keeping request body, token value,
  authorization header, response body, and network response out of the trace.
- Each run now emits `GitHubPrCreatePlan` on `runtime.github-pr-create`, with a
  `github_pr_create_plan` receipt and `github-pr-create-plan.json` artifact.
- React Flow now has a `github_pr_create` / `GitHubPrCreateNode` contract that
  consumes the PR workflow lane and exposes status, blockers, request hash,
  authority, and receipt fields.
- The default harness routes `github_pr_create` immediately after
  `review_gate`, giving workflow authors a configurable mutation boundary that
  is still dry-run/projection-only until authority and review are satisfied.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json`

### P2. Runtime Task Queue And Jobs

Problem:

DeepSeek has durable task queue and background jobs. IOI has execution queues,
but needs user-visible task/job lifecycle.

Target:

Expose durable jobs as first-class runtime records.

Runtime records:

- `RuntimeTaskRecord`;
- `RuntimeJobRecord`;
- `RuntimeChecklistRecord`;
- `VerificationGateRecord`;
- `JobArtifactRecord`.

API:

- `POST /v1/tasks`;
- `GET /v1/tasks`;
- `GET /v1/tasks/{id}`;
- `POST /v1/tasks/{id}/cancel`;
- `GET /v1/jobs`;
- `POST /v1/jobs/{id}/cancel`;

React Flow workflow surface:

- Add `TaskQueueNode`, `JobNode`, `ChecklistNode`, and `VerificationGateNode`.
- Job node can represent shell jobs, subagent jobs, hosted worker jobs, and long
  verification jobs.

Acceptance evidence:

- long-running test command survives TUI disconnect;
- cancellation emits terminal job event;
- React Flow shows running, waiting, completed, failed, and canceled jobs from
  the same event store.

Implementation slice completed 2026-05-11, runtime task/job ledger spine:

- Added durable `ioi.agent-runtime.task-record.v1` and
  `ioi.agent-runtime.job-record.v1` projections over canonical daemon runs.
- Runtime tasks now record task family, mode, selected strategy, prompt hash,
  thread/turn linkage, replayability, and redaction posture without storing the
  raw prompt in the task projection.
- Runtime jobs now record task linkage, run linkage, queue name, runner, job
  type, lifecycle, progress, endpoints, artifacts, receipts, cancellation
  state, replayability, and durability.
- Added `/v1/jobs` and `/v1/jobs/{id}` so CLI/TUI, SDK surfaces, and React Flow
  can inspect job status without reading private run internals.
- Each run now emits `RuntimeTaskRecord`, `JobQueued`, `JobStarted`, and
  `JobCompleted` TTI-visible events, with runtime task/job receipts and
  `runtime-task.json` / `runtime-job.json` artifacts.
- Cancellation updates the top-level task/job projection to `canceled` while
  preserving single-terminal-event replay semantics.
- React Flow now has `runtime_task` / `RuntimeTaskNode` and `runtime_job` /
  `RuntimeJobNode` contracts, routed after `runtime_doctor` and before
  repository/PR workflow nodes in the default harness.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json`

Implementation slice completed 2026-05-11, job cancellation endpoint:

- Added `POST /v1/jobs/{id}/cancel` as the job-facing cancellation path,
  resolving job IDs to canonical run IDs and delegating to the run cancellation
  owner.
- Job cancellation now rewrites replay to show `JobQueued`, `JobStarted`,
  `JobCanceled`, and then the single run-level `canceled` terminal event,
  avoiding duplicate terminal run events and stale `JobCompleted` lifecycle
  claims after cancellation.
- The public job record updates to `status: "canceled"` with lifecycle
  `["queued", "started", "canceled"]`, cancellation reason, cancel endpoint,
  and refreshed `runtime-job.json` artifact content.
- React Flow `runtime_job` configuration now exposes
  `runtimeJobCancelEndpoint`, `runtimeJobCancelable`, and
  `runtimeJobCancelRoute`, so workflows can model job cancellation explicitly.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json`

Implementation slice completed 2026-05-11, runtime checklist record:

- Added a durable `RuntimeChecklistRecord` projection under Agentgres
  `checklists/`, exposed in trace bundles and canonical projection paths.
- The checklist binds the runtime task, runtime job lifecycle, terminal job
  event, artifacts, receipts, replayability, and redaction posture into one
  workflow-addressable record.
- Cancellation replay now refreshes `runtime-checklist.json`, emits a
  `RuntimeChecklistRecord` TTI event, and attaches checklist IDs/status back to
  public job records.
- React Flow now has a `runtime_checklist` / `RuntimeChecklistNode` contract
  with configurable trace endpoint, checklist/status/items fields, activation
  gate consumption flags, and default harness component wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json`

### P2. Localization And Accessibility

Problem:

DeepSeek localizes TUI chrome. IOI should provide at least product-ready
localization boundaries and accessible graph status.

Target:

Add localizable runtime UI strings at client surfaces while keeping model output
language controlled by user messages and locale config.

React Flow workflow surface:

- Nodes expose accessible names;
- event status colors have text equivalents;
- keyboard navigation reaches node inspector, timeline, approvals, and run
  controls.

Acceptance evidence:

- no runtime event semantics depend on localized strings;
- TUI can switch chrome language;
- workflow canvas status remains readable without color.

Implementation slice completed 2026-05-11, runtime chrome localization and
accessible status metadata:

- Added `workflow-runtime-ui-strings.ts` as the workflow-addressable runtime
  chrome string catalog with locale keys, accessible names, status
  announcements, English/Spanish chrome strings, and explicit
  `modelOutputLocalized: false` boundary.
- Added graph config fields for `runtimeUiStringCatalogRef`, `localeKey`,
  `ariaLabelKey`, `statusAnnouncementKey`, `accessibleStatusField`,
  `accessibleStatusText`, and `colorIndependentStatus`.
- Bound localization and accessibility metadata into runtime, repository,
  branch policy, GitHub context, issue context, PR attempt, review gate, and
  GitHub PR create nodes.
- Default harness components now expose color-independent status metadata in
  component UI metadata and node logic, so React Flow can announce status
  through text instead of relying on color.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json`

Implementation slice completed 2026-05-11, workflow UI localization and
accessible status surfaces:

- Added runtime chrome string resolution helpers for locale normalization,
  keyed string interpolation, dotted status-field lookup, localized status
  labels, and node chrome bundles.
- React Flow canvas nodes now resolve runtime labels/ARIA names from the
  catalog, expose `data-accessible-status` and
  `data-accessible-status-text`, hide color-only status dots from assistive
  tech, and render the status text in the footer with polite announcement.
- The node inspector now exposes a graph-configurable `workflowChromeLocale`
  selector for runtime chrome while preserving `modelOutputLocalized: false`
  as inspectable metadata.
- The workflow rail now uses the same status label resolver for run filters,
  run cards, attempts, selected-node status, and timeline entries, with
  `aria-label` and data attributes for color-independent inspection.
- Static contract coverage now guards the shared resolver, canvas status text,
  inspector locale selector, and workflow rail timeline wiring.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json`

Implementation slice completed 2026-05-11, keyboard and focus parity:

- The React Flow canvas now injects keyboard selection callbacks into node data
  and marks the canvas with an explicit keyboard-navigation contract.
- Canvas nodes are tab stops with `aria-keyshortcuts="Enter Space"`, select the
  same inspector path on focus or Enter/Space, and expose a visible focus ring
  independent of selection color.
- Run rail timeline entries, harness attempt rows, shadow comparison rows, the
  selected-node inspector, and bottom-shelf run timelines are keyboard
  focusable with accessible labels.
- Run cards, attempts, comparison nodes, search results, harness reference
  buttons, inspector actions, and node group filters now have explicit
  focus-visible styling.
- Static contract coverage now guards the canvas keyboard handoff, node
  Enter/Space behavior, timeline tab stops, selected-node inspector focus
  target, and focus-visible CSS.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json`

Implementation slice completed 2026-05-11, global workflow chrome locale:

- Added `global_config.workflowChromeLocale` with an `en-US` default and
  normalization so workflow JSON persists a single chrome locale for the whole
  graph.
- Canvas rendering now receives the workflow locale and passes it into runtime
  node chrome resolution, while per-node `workflowChromeLocale` overrides still
  win when explicitly configured.
- The standalone graph settings inspector and workflow composer settings rail
  now expose the workflow chrome locale selector using the shared runtime UI
  string catalog.
- The workflow rail, selected-node inspector, and status label resolver now
  fall back to the global workflow chrome locale when no node override exists.
- Static contract coverage now guards persistence, defaults, graph settings,
  canvas propagation, workflow rail settings, and the global/per-node override
  boundary.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json`

Implementation slice completed 2026-05-11, locale-aware portable package
evidence:

- Portable workflow package manifests now carry
  `workflowChromeLocale` alongside source identity, readiness, harness evidence,
  and worker binding metadata.
- Package import preserves that locale even for legacy workflow JSON missing the
  global config field, so React Flow chrome remains stable across checkout
  boundaries.
- The package summary and import review surfaces expose source/imported locale
  data attributes, visible locale rows, and a preservation flag for live
  autopilot GUI evidence.
- The workflow file-bundle model now includes the package locale in its portable
  package status, keeping workflow development environment review surfaces
  auditable.
- Static contract coverage now guards the TypeScript manifest/review contracts,
  React Flow package/import data attributes, file-bundle model status, and the
  Tauri export/import locale persistence path.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json`

Implementation slice completed 2026-05-11, workflow-native package/import
actions:

- Added `WorkflowPackageExportNode` and `WorkflowPackageImportNode` as
  first-class React Flow tool nodes with typed ports, runtime chrome
  localization, accessibility status fields, policy profiles, output schemas,
  activation gates, and package evidence fields.
- The default componentized harness now includes package export/import
  components in the runtime workflow flow, promotion cluster, node type mapper,
  policy slot mapping, and node logic, so portable workflow package review is
  graph-configurable rather than only available from surrounding UI controls.
- Runtime action contracts now include `workflow_package_export` and
  `workflow_package_import`, while preserving `skill_context` as a generated
  action kind, keeping projection adapters and generated TS/Rust schemas in
  sync.
- Workflow harness tool evidence now reports package path, imported workflow
  path, readiness status, workflow chrome locale, and package evidence
  readiness so chat/tool execution and workflow execution share the same
  package review surface.
- Static contract coverage now guards graph types, node registry entries,
  default harness wiring, runtime UI strings, projection adapter mappings,
  generated action schemas, and package harness tool evidence.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json`

Implementation slice completed 2026-05-11, package action runtime execution:

- `workflow_package_export` and `workflow_package_import` now map to explicit
  Rust `ActionKind` variants, completion verification requirements, and an
  `output_bundle` connection class shared by validation and execution.
- The workflow executor now runs package export/import nodes end to end,
  delegating to the existing portable package export/import paths while
  preserving package path, manifest readiness, imported workflow path, chrome
  locale, locale preservation, mutation status, and package review evidence in
  node output.
- Workflow scaffolds/templates now expose package export/import presets,
  package output schemas, ports, action metadata, write side-effect profiles,
  dry-run support, and approval metadata for import nodes.
- Runtime verification evidence now emits package-specific evidence types for
  package export/import nodes instead of collapsing them into generic execution
  evidence.
- Rust coverage now proves a React Flow graph can execute
  `workflow_package_export -> workflow_package_import -> output`, including
  package-path handoff and workflow chrome locale preservation.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json`

Implementation slice completed 2026-05-11, package action run output
surfaces:

- Added a reusable `workflowPackageNodeOutputSummary` model helper for
  package export/import node outputs, normalizing package path, manifest path,
  readiness, portability, workflow chrome locale, imported workflow path,
  locale preservation, and package evidence readiness.
- The selected-node React Flow inspector now shows a package output summary
  when a package export/import node has a run or pinned fixture output, with
  data attributes for package kind, path, readiness, evidence, imported
  workflow, and locale preservation.
- The workflow bottom selection shelf now mirrors the package output summary so
  package execution results are visible from the run surface without opening
  the full inspector.
- The live autopilot GUI harness rollback/package proof now guards the reusable
  package-output model helper plus both visible workflow surfaces, preserving
  the componentized workflow-development contract.
- Static daemon contract coverage now guards the package output helper, the
  selected-node inspector selector, and the bottom shelf selector.

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json`
  - all retained chat scenarios passed;
  - per-slice package-output proof passed:
    `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true`;
  - full harness validation remains red on unrelated promotion-live/default
    dispatch bindings:
    `harness_promotion_transition_live_gui_interaction`,
    `harness_live_promotion_readiness`, and
    `harness_live_shadow_comparison_gate`.

## React Flow Workflow Development Environment Requirements

The workflow development environment is where IOI should exceed DeepSeek. Every
gap closure must be graph-configurable and graph-inspectable.

### Core Principle

React Flow is a workflow authoring and projection surface over canonical runtime
components. It is not an independent runtime.

### Required Graph Layers

1. Design layer:
   - user edits nodes, edges, config, policies, fixtures, and gates.
2. Validation layer:
   - graph compiles into runtime component contracts;
   - missing capabilities become activation blockers.
3. Activation layer:
   - runtime creates thread/turn/task records;
   - graph nodes receive runtime ids.
4. Execution layer:
   - events update node statuses.
5. Replay layer:
   - graph state is rebuilt from event log and receipts.
6. Fork layer:
   - users can fork a run or harness into a proposed workflow.

### Required React Flow Node Categories

Runtime:

- `RuntimeThreadNode`;
- `RuntimeTurnNode`;
- `RuntimeEventStreamNode`;
- `RuntimeDoctorNode`;
- `AgentgresProjectionNode`.

Model:

- `ModelRouterNode`;
- `ReasoningEffortNode`;
- `ContextBudgetNode`;
- `CompactionPolicyNode`.

Tools:

- `ToolPackNode`;
- `FilesystemToolNode`;
- `PatchToolNode`;
- `GitToolNode`;
- `ShellJobNode`;
- `WebToolNode`;
- `BrowserToolNode`;
- `GuiToolNode`;
- `McpToolNode`;
- `LspDiagnosticsNode`;
- `TestRunnerNode`;
- `ArtifactStoreNode`.

Safety:

- `ApprovalGateNode`;
- `PolicyDecisionNode`;
- `AuthorityScopeNode`;
- `PiiRedactionNode`;
- `SandboxProfileNode`;
- `TrustProfileNode`;

Subagents/workers:

- `SubagentPoolNode`;
- `SubagentRoleNode`;
- `SubagentSpawnNode`;
- `SubagentJoinNode`;
- `WorkerTemplateNode`;
- `HandoffQualityNode`.

Memory/skills/hooks:

- `MemoryScopeNode`;
- `MemoryInjectionNode`;
- `RememberNode`;
- `SkillPackNode`;
- `SkillNode`;
- `HookNode`.

Recovery:

- `RollbackSnapshotNode`;
- `RestoreGateNode`;
- `RetryPolicyNode`;
- `IncidentRecoveryNode`.

Verification:

- `ChecklistNode`;
- `VerificationGateNode`;
- `DiagnosticsNode`;
- `ScorecardNode`;
- `QualityLedgerNode`.

Repository:

- `RepositoryNode`;
- `BranchPolicyNode`;
- `IssueNode`;
- `PrAttemptNode`;
- `ReviewGateNode`.

### Node Contract

Every workflow node type must declare:

- `node_type`;
- `component_kind`;
- `runtime_owner`;
- `input_ports`;
- `output_ports`;
- `config_schema`;
- `capability_requirements`;
- `authority_scope_requirements`;
- `approval_profile`;
- `event_kinds_emitted`;
- `receipt_kinds_emitted`;
- `artifact_kinds_emitted`;
- `replay_behavior`;
- `rollback_behavior`;
- `validation_rules`;
- `default_visual_status`.

### Edge Contract

Every edge must declare:

- source node and port;
- target node and port;
- payload type;
- ordering semantics;
- backpressure behavior;
- cancellation propagation;
- failure propagation;
- replay semantics.

### Graph Compilation Contract

Graph activation produces:

- runtime component manifest;
- tool registry manifest;
- model routing manifest;
- approval/policy manifest;
- memory/skills/hooks manifest;
- subagent manifest;
- artifact retention manifest;
- test/fixture manifest;
- schema hash;
- activation receipt.

Compilation must fail if:

- a node has no runtime owner;
- a mutating node lacks policy posture;
- a connector node lacks authority scope mapping;
- a tool node lacks a generated tool contract;
- an edge connects incompatible payload types;
- a subagent node exceeds configured concurrency cap;
- a rollback policy references no snapshot component;
- a graph uses synthetic runtime mode outside explicit fixture profile.

### Workflow UX Requirements

Workflow users must be able to:

- import a DeepSeek-style coding-agent default graph;
- inspect the default IOI harness graph read-only;
- fork the default harness as a proposal;
- configure tool packs by node;
- configure model routing by node or graph;
- set approval and trust profiles;
- attach MCP servers;
- enable LSP diagnostics;
- set rollback policy;
- configure memory and skills;
- configure subagent pools;
- activate graph only after validation;
- replay a run and see events animate through nodes;
- jump from any TUI event to the corresponding graph node;
- jump from any graph node to its runtime events, receipts, artifacts, and logs.

## Implementation Roadmap

### Phase 0. Contract Lock

Goal:

Freeze target contracts before implementation churn.

Deliverables:

- TTI schema draft;
- public event envelope schema;
- workflow node contract schema;
- tool contract to React Flow node mapping;
- mode/approval profile schema;
- runtime doctor schema.

Files likely touched:

- `crates/types/src/app/agentic/*`;
- `crates/types/src/app/harness.rs`;
- `docs/implementation/runtime-action-schema.json`;
- `packages/agent-ide/src/runtime/workflow-schema.ts`;
- `packages/agent-ide/src/runtime/graph-runtime-types.ts`;
- generated TS schema files.

Validation:

- schema snapshot tests;
- Rust/TS schema parity tests;
- graph compilation fixture tests.

### Phase 1. Live Runtime API And Event Store

Goal:

Replace production synthetic daemon runs with live runtime-backed threads and
turns.

Deliverables:

- `RuntimeApiBridge`;
- event writer;
- TTI projection;
- `/v1/threads/*`;
- SSE replay;
- SDK wrapper;
- CLI stream command.

Validation:

- live runtime smoke test;
- reconnect test;
- replay determinism test;
- synthetic path fail-closed test.

### Phase 2. Coding Tool Pack, Jobs, Artifacts

Goal:

Make IOI usable as a coding agent without relying on ad hoc shell fallbacks.

Deliverables:

- coding tool pack;
- git tools;
- apply patch tool;
- test runner;
- diagnostics;
- tool-output artifacts;
- job center.

Validation:

- coding fixture: inspect, patch, test, diagnose, summarize;
- large output spillover test;
- tool contract generation test;
- React Flow node config disables/enables specific tools.

### Phase 3. LSP And Rollback

Goal:

Close the two high-leverage coding feedback loops.

Deliverables:

- LSP runtime component;
- post-edit diagnostics hook;
- model-callable LSP navigation tools;
- workspace snapshot service;
- restore API and TUI UX;
- React Flow rollback nodes.

Validation:

- language fixture diagnostics;
- missing LSP degrade test;
- snapshot and restore canary;
- React Flow restore-gate activation test.

### Phase 4. TUI Product Surface

Goal:

Provide the terminal coding-agent experience.

Deliverables:

- `ioi agent tui`;
- mode/model/thinking controls;
- slash commands;
- approval modal;
- jobs/subagents panel;
- cost/context footer;
- workflow deep links.

Validation:

- start/resume/interrupt run from TUI;
- approval round-trip;
- reconnect after terminal close;
- same thread visible in SDK and React Flow.

### Phase 5. Subagents, MCP, Memory, Skills, Hooks

Goal:

Productize extensibility.

Deliverables:

- subagent manager API/tools;
- role taxonomy;
- MCP manager parity;
- tool-search/deferred MCP exposure;
- memory UX;
- skill discovery/import;
- hook lifecycle.

Validation:

- parallel subagent fixture;
- MCP import/invoke/disable fixture;
- memory remember fixture;
- skill import fixture;
- hook failure policy fixture;
- React Flow subagent/MCP/memory graph tests.

### Phase 6. Usage, Doctor, Auto-Routing

Goal:

Make runtime behavior understandable and tunable.

Deliverables:

- usage API;
- cost/context telemetry;
- doctor endpoint;
- model auto-routing events;
- graph budget controls.

Validation:

- usage aggregation test;
- budget stop test;
- doctor degraded environment test;
- auto route fallback test.

### Phase 7. Hosted/Repository/PR Plus

Goal:

Exceed DeepSeek for team coding workflows.

Deliverables:

- repository context service;
- GitHub/PR tools;
- hosted worker profile;
- branch policy;
- PR attempt receipts;
- review gates.

Validation:

- governed PR creation test with mocked authority;
- hosted worker fail-closed when unavailable;
- graph review gate blocks PR creation;
- branch artifact and diff replay.

## Cross-Surface Parity Matrix

| Capability | Runtime | Daemon/API | SDK | CLI/TUI | React Flow |
| --- | --- | --- | --- | --- | --- |
| Threads/turns/items | `AgentState` projection plus TTI records | `/v1/threads/*` | `Thread`, `Turn`, `Run` | `/threads`, `/events` | thread/turn/event nodes |
| Live events | event writer | SSE by `seq` | async iterators | stream/replay | replay animation |
| Modes | runtime mode/profile | thread/turn mode fields | options | Plan/Agent/YOLO | graph mode selector |
| Coding tools | coding tool pack | `/v1/tools` | generated types | slash commands | tool-pack nodes |
| Jobs | job manager | `/v1/jobs` | job handles | `/jobs` | job nodes |
| LSP | LSP runtime | diagnostic events | diagnostic items | diagnostics panel | LSP node/overlay |
| Rollback | snapshot service | snapshot API | restore helpers | `/restore` | rollback nodes |
| Subagents | subagent manager | subagent endpoints/tools | spawn/wait wrappers | side panel | subagent subflows |
| MCP | `McpManager` | MCP registry/API | MCP options | `/mcp` | MCP nodes |
| Memory | memory runtime | memory endpoints/events | memory helpers | `/memory`, `#` | memory nodes |
| Skills/hooks | prompt/hook components | config/introspection | skill/hook options | `/skills`, `/hooks` | skill/hook nodes |
| Usage/cost | usage normalizer | `/v1/usage` | usage methods | `/cost` | usage/budget nodes |
| Doctor | runtime health | `/v1/doctor` | doctor method | `doctor --json` | readiness panel |
| Model routing | route decision component | route events | route metadata | `/model`, `/thinking` | model-router node |
| Repository/PR | repo services | repo/PR endpoints | repo helpers | repo commands | repo/PR nodes |

## Prompt And System Instruction Updates

When the coding tool pack and TUI land, update runtime prompts to prefer:

- structured file/search/git/test/diagnostic tools over shell;
- `file__apply_patch` for multi-hunk code edits;
- `tool__retrieve_result` for large outputs;
- `test__run` and `lsp__diagnostics` before claiming completion;
- subagents for independent parallel exploration or verification;
- workflow proposal nodes for harness/workflow edits;
- approval explanations that mention policy, capability, and authority scope.

Prompts must avoid telling the model that React Flow is the runtime. The model
should treat graph nodes as configured runtime components and projections.

## Evidence Bundle Requirements

Every phase must produce an evidence bundle under `docs/evidence/` with:

- `result.json`;
- event replay file;
- trace bundle;
- workflow graph fixture;
- screenshots for React Flow/TUI where relevant;
- receipt summary;
- test command output summary;
- known blockers;
- residual risk.

Minimum final parity evidence:

- one coding run started from TUI and replayed in React Flow;
- one coding run started from SDK and inspected in TUI;
- one workflow graph activation producing a live runtime thread;
- one LSP diagnostic feedback loop;
- one restore canary;
- one MCP import and governed tool call;
- one subagent parallel fan-out;
- one memory remember and injection;
- one usage/cost report;
- one doctor degraded-environment report;
- one PR attempt or explicit hosted-blocker report.

## Definition Of Done

This guide is complete when:

1. Production daemon runs are live runtime-backed, not synthetic.
2. TTI records and monotonic events are canonical public API surfaces.
3. The TUI supports real coding-agent workflows with modes, approvals, jobs,
   restore, MCP, memory, usage, and subagents.
4. Coding tool parity is available without shell-only fallbacks.
5. LSP diagnostics and workspace rollback are automatic and inspectable.
6. MCP, skills, hooks, memory, and subagents are productized.
7. Usage/cost/context telemetry and doctor reports are stable.
8. Every capability is configurable in the React Flow workflow development
   environment.
9. React Flow can compile, activate, replay, and fork runtime graphs without
   owning runtime truth.
10. SDK, CLI/TUI, daemon, Autopilot, and React Flow all consume the same runtime
    events, contracts, receipts, artifacts, and graph activation records.

## First Implementation Slice

Start with the smallest slice that breaks the most risk:

1. Define TTI and event envelope schemas.
2. Bridge one live `RuntimeAgentService` session into `/v1/threads/{id}/events`.
3. Add a minimal React Flow runtime thread/turn/event projection.
4. Add one coding tool node mapped to an existing tool contract.
5. Prove a live event appears in SDK, CLI, and React Flow from the same `seq`.

Do not start with the full TUI. The TUI becomes straightforward once live
threads, events, and tool contracts are real.
