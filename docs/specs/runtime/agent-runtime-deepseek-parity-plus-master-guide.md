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

Implementation slice completed 2026-05-11, live shadow promotion/default
dispatch binding:

- The default authority-tooling gate now includes the `github_pr_create`
  adapter envelope, so PR-create dry-run planning participates in the same
  node-authoritative live shadow path as policy, approval, MCP, native tool,
  connector, and wallet capability calls.
- Authority-tooling live-readiness no longer relies on a stale hard-coded
  adapter count. It derives readiness from
  `DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS`, preserving the
  componentized harness contract as new tool adapters are added.
- The live GUI harness now treats the workflow proof's live shadow comparison
  gate as authoritative evidence for promotion readiness when the chat artifact
  summary has not yet emitted every required component pair, and the result
  artifact points to the proof file containing the 21-component gate.
- Static contract coverage now guards the `github_pr_create` adapter envelope,
  its node-authority component membership, and its live shadow comparison gate
  membership.
- The previous package-output evidence run's red promotion-live cascade is now
  closed: runtime selector default promotion, default dispatch binding, live
  promotion readiness, authority-tooling node authority, and the live shadow
  comparison gate all validate green.

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- focused default dispatch proof: live mode, 21/21 shadow comparisons,
  `github_pr_create` present, no live promotion blockers.
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json`
  - `validation.ok === true`;
  - no false artifacts;
  - `harness_live_promotion_readiness_present === true`;
  - `harness_live_shadow_comparison_gate_present === true`;
  - proof gate has `comparisonCount === 21`, `requiredComparisonCount === 21`,
    and includes `github_pr_create`.

Implementation slice completed 2026-05-11, direct PR-create live shadow
artifact emission:

- The default harness now emits the `github_pr_create` live/shadow comparison
  directly from `runtime-artifacts.json`; the validator no longer needs to rely
  on promotion proof fallback to prove the 21st authority-tooling pair.
- `HarnessComponentKind::GithubPrCreate` is now part of the componentized
  default flow, authority-tooling cluster, live shadow comparison gate, replay
  policy, approval semantics, tool-grant slot policy, canary boundary, and
  default dispatch proof fixture.
- The Rust default dispatch path now executes a read-only
  `github__pr_create` dry-run plan node, records attempt/receipt/replay refs,
  blocks mutation, and exposes `authorityToolingGithubPrCreateDryRun*` summary
  fields beside MCP, native tool, connector, and wallet authority evidence.
- The React Flow/workflow GUI validator contract now requires
  `harness_authority_tooling_github_pr_create_dry_run` as a first-class runtime
  artifact and consistency bit.
- Live artifact proof:
  `runtime-artifacts.json` now reports `harnessLiveShadowComparisonCount === 21`,
  includes `github_pr_create` in `harnessLiveShadowComparisonComponentKinds`,
  and reports `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Validation evidence:

- `cargo test -p ioi-types harness -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml default_runtime_dispatch_accepts_isolated_output_writer_staged_write_canary -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml save_local_task_state_exports_gui_runtime_evidence_projection -- --nocapture`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json`
  - `validation.ok === true`;
  - runtime consistency includes
    `harness_authority_tooling_github_pr_create_dry_run_present === true`;
  - `runtime-artifacts.json` has the direct 21/21 component set with
    `github_pr_create`.

Implementation slice completed 2026-05-11, PR-create workflow output surfaces:

- The React Flow selected-node inspector now treats `github_pr_create` dry-run
  plans as first-class run output, beside the existing package action output
  surface.
- Added a reusable `workflowGithubPrCreatePlanSummary` model helper that
  normalizes nested or direct `githubPrCreatePlan` payloads into request hash,
  dry-run/preview flags, mutation-attempt/executed flags, network lookup state,
  missing authority scopes, review gate status, receipt id, blockers, and
  evidence refs.
- The selected-node inspector now exposes
  `workflow-selected-node-github-pr-create-output-summary` with data attributes
  for request hash, `dryRun`, mutation state, missing `github.pr.create` scope,
  review gate status, receipt refs, replay fixture ref, request body/token
  redaction, and blocker/evidence refs.
- The workflow bottom selection shelf mirrors the PR-create output summary with
  `workflow-selection-github-pr-create-output-summary`, so operators can inspect
  the dry-run result without opening the full inspector.
- The live GUI harness now validates the surface in two ways:
  static source-contract proof in `rollback-restore-canary-ui-proof.json`, and
  a React-rendered selected-node proof in
  `promotion-transition-gui-behavior-proof.json` that selects
  `harness.github_pr_create` and verifies request hash, dry-run/mutation flags,
  missing scope, review gate status, receipt refs, and replay fixture refs.

Validation evidence:

- `npm run build:ide -- --pretty false`
- `node --check scripts/lib/harness-promotion-transition-gui-probe.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `TSX_TSCONFIG_PATH=packages/agent-ide/tsconfig.json node --import tsx packages/agent-ide/src/runtime/workflow-rail-receipts.test.ts`
- targeted React render proof:
  `node --import tsx scripts/lib/harness-promotion-transition-gui-probe.mjs /tmp/github-pr-create-workflow-node-probe.json`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json`
  - `validation.ok === true`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `promotion-transition-gui-behavior-proof.json` has
    `checks.githubPrCreateNodeOutputInspector === true`;
  - `runtime-artifacts.json` retains the direct 21/21 live shadow component set
    with `github_pr_create` and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, PR-create React Flow runtime execution:

- The Rust workflow runtime now recognizes `repository_context`,
  `branch_policy`, `github_context`, `issue_context`, `pr_attempt`,
  `review_gate`, and `github_pr_create` as executable action kinds instead of
  unsupported projection-only nodes.
- React Flow graphs can now execute the full repository-to-PR lane:
  `repository_context -> branch_policy -> github_context -> issue_context ->
  pr_attempt -> review_gate -> github_pr_create -> output`.
- `github_pr_create` remains dry-run-only in the Rust executor. It returns the
  same safe `ioi.agent-runtime.github-pr-create-plan.v1` shape used by the
  daemon/UI contract: request method/path, 64-character payload hash, no request
  body/token/authorization/network response, missing `github.pr.create`
  authority, review blockers, `dryRun: true`, `previewOnly: true`,
  `networkLookupPerformed: false`, `mutationAttempted: false`, and
  `mutationExecuted: false`.
- Runtime validation now understands the repository-lane state/approval/data
  port classes, so workflow authors can connect the lane with named React Flow
  ports instead of relying on generic `input`/`output` edges.
- The workflow templates now expose repository-lane node ports, default dry-run
  logic, and the `workflow_github_pr_create_output_schema`, keeping the modular
  component graph authorable through the workflow development environment.
- Runtime verification evidence now records repository-lane evidence types,
  including `github_pr_create`, rather than collapsing the PR-create execution
  into generic `execution`.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` source-contract proof now includes
    `ActionKind::GithubPrCreate`,
    `workflow_github_pr_create_output`, and
    `github_pr_create_dry_run_node_executes_through_runtime`.

Implementation slice completed 2026-05-11, PR-create runtime module refactor:

- The repository-to-PR runtime lane now lives in
  `apps/autopilot/src-tauri/src/project/repository_pr_lane.rs`, keeping
  `runtime.rs` focused on action dispatch, package import/export execution,
  harness runtime projection, and shared workflow mechanics.
- The extracted lane owns the output builders for `repository_context`,
  `branch_policy`, `github_context`, `issue_context`, `pr_attempt`,
  `review_gate`, and dry-run-only `github_pr_create`, preserving the same safe
  plan shape and mutation/network boundaries from the prior slice.
- The daemon and live GUI source-contract proofs now read
  `repository_pr_lane.rs` directly while still checking that `runtime.rs`
  dispatches `ActionKind::GithubPrCreate`, so parity evidence follows the
  modular architecture instead of assuming every executor lives in one file.
- The live GUI validation initially exposed a transient retained
  `probe_behavior` submit timeout unrelated to this refactor. A clean rerun
  completed the full chat/workflow evidence ladder and is the slice's canonical
  proof artifact.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow value helper extraction:

- Shared workflow JSON/path/hash primitives now live in
  `apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`.
- `runtime.rs` and `repository_pr_lane.rs` import the same helper module for
  multi-key string/bool/u64 lookup, string-array normalization, workflow
  project-root resolution, dotted-path value lookup, and raw JCS hash
  generation.
- This keeps the componentized runtime architecture ready for the next lane:
  new executable React Flow components can reuse the same workflow value
  semantics instead of copying local helper functions into each module.
- The daemon and live GUI source-contract proofs now verify the helper module
  boundary directly while retaining the existing PR-create runtime execution
  and dry-run safety assertions.

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow package lane refactor:

- Workflow package export/import execution now lives in
  `apps/autopilot/src-tauri/src/project/workflow_package_lane.rs`, matching the
  repository PR lane pattern and keeping `runtime.rs` focused on dispatch and
  shared run mechanics.
- The package lane owns `execute_workflow_package_export_node`,
  `execute_workflow_package_import_node`, package path resolution, package-path
  deep input lookup, import review construction, locale preservation checks, and
  package evidence readiness projection.
- `workflow_logic_string` moved into `workflow_value_helpers.rs` so package,
  PR, and runtime dispatch code share the same trimmed workflow config lookup
  semantics.
- The daemon and live GUI source-contract proofs now assert that
  `runtime.rs` dispatches `WorkflowPackageExport` / `WorkflowPackageImport`
  through `workflow_package_lane.rs`, while the lane retains package output
  surfaces and `workflowPackageImportReview` evidence.

Validation evidence:

- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true` and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow memory lane refactor:

- Workflow memory send-policy and memory search/list execution now live in
  `apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs`, keeping
  `runtime.rs` focused on dispatch, model/state assembly, and shared run
  mechanics.
- The memory lane owns `workflow_memory_send_options`,
  `workflow_memory_query_output`, `memory_search`, `memory_list`, memory record
  collection, search-text normalization, and redacted fact hashing for
  workflow-visible memory outputs.
- `workflow_sha256_hex` moved into `workflow_value_helpers.rs` so memory
  redaction, skill guidance hashing, and future executable React Flow lanes use
  one shared hash primitive instead of each lane carrying a local copy.
- The daemon and live GUI source-contract proofs now assert that memory policy
  and memory query execution are lane-owned while `runtime.rs` continues to
  expose memory behavior through graph-addressable ModelCall and State nodes.
- This preserves the React Flow workflow development requirement that memory
  send policy and memory search/list behavior remain configurable and
  inspectable from the workflow graph, while the Rust runtime stays modular
  enough to keep extracting lanes without bloating `runtime.rs`.

Validation evidence:

- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, authority/tooling lane refactor:

- MCP provider catalog, MCP tool catalog, native tool catalog, connector catalog
  describe, wallet capability dry-run, authority policy gate, authority
  approval gate, and destructive-denial execution now live in
  `apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs`.
- `runtime.rs` keeps the graph dispatch branches for AdapterConnector,
  PluginTool, Decision, and HumanGate, but imports the lane-owned helpers for
  live read-only catalog projection, approval denial, wallet no-grant receipts,
  and mutation-safe destructive denial.
- The side-effect live-runtime classifier moved with the authority/tooling lane
  and is imported by validation so graph readiness checks and runtime execution
  use one policy source.
- `workflow_hash_value` moved into `workflow_value_helpers.rs`, preserving the
  canonical JCS hash behavior used by runtime attempt hashes and authority
  catalog linkage hashes.
- The daemon and live GUI source-contract proofs now assert that
  `workflow_authority_tooling_lane.rs` owns all authority/tooling live helpers
  while React Flow remains able to configure and inspect the same authority,
  catalog, connector, and wallet-capability nodes.

Validation evidence:

- `cargo test live_mcp_provider_catalog_executes_read_only_without_mutation --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_mcp_tool_catalog_consumes_provider_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_native_tool_catalog_consumes_mcp_tool_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_connector_catalog_describe_consumes_mcp_tool_catalog_without_connector_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_wallet_capability_dry_run_never_materializes_grant --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_destructive_denial_blocks_without_side_effect --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_approval_gate_denies_without_authority_transfer --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `approval_gate`, `policy_gate`, `connector_call`, `mcp_provider`,
    `mcp_tool_call`, `tool_call`, `wallet_capability`, and `github_pr_create`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingProviderCatalogLiveCount === 5`,
    `harnessAuthorityToolingMcpToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingNativeToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingConnectorCatalogLiveCount === 5`,
    `harnessAuthorityToolingWalletCapabilityLiveDryRunCount === 5`, and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow coding-route lane refactor:

- Skill-context resolution and coding-route evidence generation now live in
  `apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs`.
- The lane owns `WorkflowSkillResolver`, `resolve_skill_context`, route
  classification, phase selection, skill selection, route gates, benchmark
  results, promotion decisions, run-summary projection, and verification
  evidence projection.
- `runtime.rs` keeps graph dispatch, node lifecycle, and run assembly, but
  imports the lane-owned skill resolver and route-evidence helpers instead of
  carrying the coding-route implementation inline.
- `commands.rs` imports the same resolver for create/run command paths, so
  direct workflow runs and React Flow triggered runs use one skill catalog
  resolver.
- The GUI proof collector and daemon contract test now assert the lane boundary
  directly while preserving React Flow configurability for Skill Context nodes,
  coding-route templates, route evidence inspection, draft skill import,
  benchmark-backed promotion, and forkable promotion evidence.
- `runtime.rs` is reduced to 3,570 lines and the coding-route lane is 1,171
  lines, keeping the modular extraction trend visible before the next runtime
  slice.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `workflow-skill-context-proof.json` has `passed === true` with
    `checks.resolverExecution === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.draftBenchmarkSelection === true` and
    `checks.promotionRuntime === true`.

Implementation slice completed 2026-05-11, workflow execution-results lane
refactor:

- Workflow run-result assembly now lives in
  `apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs`.
- The lane owns `WorkflowRunResultParts`, `workflow_finalize_run_result`,
  `workflow_run_result_from_parts`, node-run verification evidence projection,
  completion requirement projection, missing-completion detection, route
  evidence attachment, route run-summary attachment, and persisted run-result
  save-through.
- `runtime.rs` keeps node execution, checkpoints, interrupt handling, and
  harness-attempt attachment, but all validation-blocked, interrupted, normal,
  and single-node exits now finalize through one lane-owned result envelope.
- The lane uses local node/edge readers plus `ActionKind` and
  `completion_requirement_kinds`, so completion evidence remains tied to the
  canonical runtime projection contract without depending on `runtime.rs` node
  helper internals.
- The daemon and live GUI source-contract proofs now assert the execution
  results lane directly while preserving React Flow run summaries, verification
  evidence, route evidence, package output surfaces, PR-create output surfaces,
  and harness rollback/restore proof inspection.
- `runtime.rs` is reduced to 3,394 lines and the execution-results lane is 258
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowExecutionResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.promotionRuntime === true`.

Implementation slice completed 2026-05-11, workflow harness-results lane
refactor:

- Harness run artifact assembly now lives in
  `apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs`.
- The lane owns harness detection, harness metadata fallback resolution,
  activation id resolution, execution mode/status mapping, per-node attempt
  construction, input/output JCS hashing, replay/receipt/evidence refs, shadow
  comparison records, gated promotion cluster runs, and
  `workflow_attach_harness_run_artifacts`.
- `runtime.rs` keeps node execution, checkpoints, interrupt handling, and run
  exits, but calls the lane helper before result finalization so validation
  blocked, interrupted, normal, and single-node exits all share the same
  harness artifact attachment boundary.
- `workflow_execution_results_lane.rs` remains the consumer of prepared harness
  artifact vectors, while the harness lane keeps the per-node
  `harness_attempt` mutation local to artifact attachment.
- The daemon and live GUI source-contract proofs now assert the harness-results
  lane directly, preserving React Flow/workflow inspection of rollback/restore,
  shadow comparison, gated promotion clusters, package outputs, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 3,097 lines; the new harness-results lane is 320
  lines, and the execution-results lane remains 258 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowHarnessResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow graph-execution lane
refactor:

- Graph edge semantics and scheduler readiness now live in
  `apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs`.
- The lane owns edge endpoint readers, edge port readers, connection-class
  fallback, incoming connection-class checks, branch-selected edge checks, node
  readiness, next-ready queue projection, and node lifecycle step projection.
- `runtime.rs` keeps the execution loop, node dispatch, checkpoints, interrupts,
  and run-result assembly, but imports graph execution helpers from the lane
  when seeding the active queue, extending ready nodes, and recording lifecycle
  steps.
- `commands.rs`, `validation.rs`, and runtime graph-contract tests continue to
  consume the same canonical graph helpers through `project.rs`, so React Flow
  validation, activation, and runtime execution share one scheduler/edge
  semantics source.
- The daemon and live GUI source-contract proofs now assert the graph-execution
  lane directly, preserving graph-configurable branch routing, connection-class
  readiness, lifecycle projection, rollback/restore inspection, package output
  surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,977 lines; the new graph-execution lane is 135
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowGraphExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow binding lane refactor:

- Node binding/config preflight now lives in
  `apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs`.
- The lane owns node schema extraction, function/tool/parser/model/connector
  binding readers, sandbox policy fallback, sandbox permission checks,
  function dependency manifest checks, and function input/output schema
  resolution.
- `runtime.rs` keeps execution dispatch, function sandbox execution, output
  materialization, approval previews, checkpoints, and run-result assembly, but
  imports binding/preflight helpers from the lane before executing graph-authored
  nodes.
- `commands.rs`, `validation.rs`, and runtime graph-contract tests continue to
  consume the same canonical binding helpers through `project.rs`, so React Flow
  graph configuration, validation, dry-run commands, and runtime execution share
  one binding readiness source.
- The output node bundle schema fallback remains private to binding schema
  extraction for this slice; output bundle materialization itself remains in
  `runtime.rs` for a later output lane extraction.
- The daemon and live GUI source-contract proofs now assert the binding lane
  directly, preserving graph-configurable function, tool, parser, model, and
  connector readiness through live workflow validation.
- `runtime.rs` is reduced to 2,757 lines; the new binding lane is 251 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowBindingRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow output lane refactor:

- Output schema satisfaction, sandbox stderr truncation, and output
  bundle/materialization projection now live in
  `apps/autopilot/src-tauri/src/project/workflow_output_lane.rs`.
- The lane owns `workflow_output_satisfies_schema`,
  `workflow_truncate_output`, `workflow_output_bundle`, renderer refs, delivery
  targets, output versioning, and materialized asset projection.
- `runtime.rs` keeps execution dispatch, function sandbox execution,
  approval/interrupt handling, checkpoints, and run-result assembly, but
  delegates function-output schema checks and `ActionKind::Output` bundle
  construction to the lane.
- `commands.rs` continues to consume the same output schema validator through
  `project.rs`, so fixture validation, dry-run output checks, and runtime output
  nodes share one artifact contract.
- The output node bundle schema fallback remains in `workflow_binding_lane.rs`;
  this output lane owns runtime artifact materialization rather than binding
  schema extraction.
- The daemon and live GUI source-contract proofs now assert the output lane
  directly, preserving React Flow inspection of output bundles, renderer refs,
  materialized assets, delivery targets, package output surfaces, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 2,672 lines; the output lane is 92 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowOutputRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-11, workflow approval/interrupt lane
refactor:

- Runtime approval binding, contextual approval previews, interrupt prompts,
  interrupt notices, and pending interrupt record construction now live in
  `apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs`.
- The lane owns `workflow_runtime_approval_binding`,
  `workflow_runtime_approval_preview`, `workflow_runtime_interrupt_prompt`,
  `workflow_runtime_interrupt_notice`, and `workflow_runtime_interrupt`.
- Approval payload construction covers connector/tool side effects, workflow
  package imports, live GitHub PR creation, and output delivery targets that
  require approval.
- `runtime.rs` keeps the execution loop, resume matching, checkpoint writes,
  event emission, interrupt persistence, thread updates, and final run-result
  assembly, but delegates approval/interrupt payload construction to the lane.
- This keeps React Flow approval gates inspectable without moving durable
  checkpoint/run orchestration into a partial lane too early.
- The daemon and live GUI source-contract proofs now assert the approval lane
  directly, preserving graph-configurable human gates, contextual tool/output
  approvals, package output surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,551 lines; the approval/interrupt lane is 152
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowApprovalInterruptRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow checkpoint lane refactor:

- Checkpoint state mutation, checkpoint id creation, active queue normalization,
  `WorkflowCheckpoint` construction, and checkpoint persistence now live in
  `apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs`.
- The lane owns `workflow_checkpoint_state` and keeps the existing helper
  contract stable for both runtime execution and checkpoint fork commands.
- `runtime.rs` keeps execution orchestration, resume matching, interrupt
  branching, retry/failure decisions, thread updates, and final run-result
  assembly, but delegates durable checkpoint construction and persistence to
  the lane.
- `commands.rs` continues to consume the same checkpoint helper through
  `project.rs`, so checkpoint forks and runtime checkpoints share one state
  snapshot contract.
- The daemon and live GUI source-contract proofs now assert the checkpoint lane
  directly, preserving React Flow inspection of checkpoint-backed interrupts,
  repaired resumes, retry evidence, package output surfaces, and PR-create
  output surfaces.
- `runtime.rs` is reduced to 2,524 lines; the checkpoint lane is 33 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowCheckpointRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow state/input mapping lane
refactor:

- Workflow expression reference discovery, sample-schema inference,
  object-like schema checks, declared output schema projection, field-path
  checks, output-port checks, expression validation, predecessor-output
  resolution, mapped node input construction, expression source extraction, and
  selected-output projection now live in
  `apps/autopilot/src-tauri/src/project/workflow_state_lane.rs`.
- The lane owns `collect_workflow_expression_refs`, `workflow_schema_from_sample`,
  `workflow_schema_is_object_like`, `workflow_node_declared_output_schema`,
  `workflow_schema_has_field_path`, `workflow_node_has_output_port`,
  `validate_workflow_expression_refs`, `workflow_predecessor_output`,
  `workflow_first_expression_source`, `workflow_mapped_node_input`, and
  `workflow_selected_output`.
- `runtime.rs` keeps execution dispatch, scheduler checks, retry/failure
  branches, checkpoints, approvals, interrupts, and run-result assembly, but
  delegates predecessor input assembly and decision selected-output projection
  to the lane.
- `validation.rs` continues to consume the same schema/object and expression
  reference helpers through `project.rs`, so React Flow graph validation and
  runtime node execution share one input-mapping and field-mapping contract.
- The daemon and live GUI source-contract proofs now assert the state lane
  directly, preserving React Flow inspection of field mappings, expression
  references, mapped inputs, selected decision outputs, checkpoint-backed
  resumes, package output surfaces, and PR-create output surfaces.
- `runtime.rs` is reduced to 2,166 lines; the state lane is 367 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_require_declared_schema_paths --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowStateRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow node-execution lane
refactor:

- Workflow tool child-run binding execution, model attachment discovery,
  function-node sandbox execution, all `ActionKind` node dispatch branches, and
  the harness canary/live-default node execution entrypoints now live in
  `apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs`.
- The lane owns `execute_workflow_tool_binding`,
  `workflow_model_ref_from_input`, `workflow_inputs_by_kind`,
  `execute_workflow_function_node`, `execute_workflow_node`,
  `execute_workflow_harness_canary_node`, and
  `execute_workflow_harness_live_default_node`.
- `runtime.rs` keeps scheduler order, retry loops, approval/interrupt
  branching, checkpoint creation, event emission, completion requirements, and
  run-result assembly, but delegates per-node execution and harness single-node
  execution to the lane.
- Node-kind execution dependencies for repository context, PR creation,
  package import/export, memory queries, binding materialization, output
  bundles, approval dry-runs, MCP/native tool catalogs, and function sandboxing
  are now source-proved through the node-execution lane. This keeps React Flow
  graph execution inspectable without forcing scheduler concerns into node-kind
  component code.
- The daemon and live GUI source-contract proofs now assert the node-execution
  lane directly while preserving the prior state, checkpoint, approval,
  output, binding, graph, harness-results, execution-results, authority/tooling,
  memory, package output, and PR-create output proofs.
- `runtime.rs` is reduced to 1,233 lines; the node-execution lane is 939 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow node-contract lane
refactor:

- Workflow action-frame projection, binding reference projection, action
  policy projection, port connection-class lookup, default connection-class
  rules, edge-port validation, and retry/max-attempt metadata now live in
  `apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs`.
- The lane owns `workflow_action_frame`,
  `workflow_node_port_connection_class`,
  `workflow_default_port_connection_class`, `validate_workflow_edge_ports`,
  and `workflow_max_attempts`.
- `runtime.rs` keeps event emission, scheduler order, retry loops,
  approval/interrupt branching, checkpoint creation, completion requirements,
  and run-result assembly, but delegates retry budget lookup and static
  node/port contract projection to the lane.
- `validation.rs`, `workflow_state_lane.rs`, and
  `workflow_node_execution_lane.rs` now share the same node-contract helpers
  through `project.rs`, keeping React Flow graph validation, expression
  validation, and per-node runtime execution on one connection-class and
  action-frame contract.
- The daemon and live GUI source-contract proofs now assert the node-contract
  lane directly while preserving the node-execution, state, checkpoint,
  approval, output, binding, graph, harness-results, execution-results,
  authority/tooling, memory, package output, and PR-create output proofs.
- `runtime.rs` is reduced to 910 lines; the node-contract lane is 328 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeContractRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow run-lifecycle lane
refactor:

- Workflow stream-event emission, thread creation, initial state construction,
  and single-node run assembly now live in
  `apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs`.
- The lane owns `workflow_push_event`, `new_workflow_thread`,
  `initial_workflow_state`, and `workflow_single_node_result`.
- `runtime.rs` keeps the multi-node scheduler loop, approval/interrupt
  branching, retry loops, checkpoint sequencing, and run completion path, but
  delegates stream-event construction and single-node run lifecycle assembly to
  the run-lifecycle lane.
- `workflow_single_node_result` still uses the same checkpoint,
  node-execution, lifecycle-step, harness-artifact, completion-requirement, and
  run-finalization helpers, preserving package export/import, PR-create dry run,
  contextual approval, memory lineage, and output delivery behavior.
- The daemon and live GUI source-contract proofs now assert the run-lifecycle
  lane directly while preserving the node-contract, node-execution, state,
  checkpoint, approval, output, binding, graph, harness-results,
  execution-results, authority/tooling, memory, package output, and PR-create
  output proofs.
- `runtime.rs` is reduced to 654 lines; the run-lifecycle lane is 269 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowRunLifecycleRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow node-metadata lane
refactor:

- Workflow node metadata extraction now lives in
  `apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs`.
- The lane owns `workflow_value_string`, `workflow_node_id`,
  `workflow_node_type`, `workflow_node_name`, `workflow_node_logic`,
  `workflow_node_law`, and `workflow_node_by_id`.
- `workflow_run_lifecycle_lane.rs` no longer imports node metadata back from
  `runtime.rs`; runtime, run-lifecycle, node-contract, node-execution,
  state/input mapping, approval/interrupt, package export/import, and
  validation now consume the same neutral metadata helper lane.
- `runtime.rs` is reduced to 617 lines; the node-metadata lane is 43 lines.
- The daemon and live GUI source-contract proofs now assert the node-metadata
  lane directly, including the no-back-reference contract from run lifecycle
  into runtime, while preserving the run-lifecycle, node-contract,
  node-execution, state, checkpoint, approval, output, binding, graph,
  harness-results, execution-results, authority/tooling, memory, package
  output, and PR-create output proofs.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/package.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeMetadataRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler lane refactor:

- The multi-node workflow orchestration function now lives in
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs`.
- The lane owns `execute_workflow_project` and its scheduler loop: validation
  blocking, ready-queue progression, approval/interrupt pause handling, retry
  attempts, state writes, checkpoint sequencing, child-run/output events,
  completion requirements, harness artifact attachment, and final run-result
  assembly.
- `apps/autopilot/src-tauri/src/project/runtime.rs` is now a 3-line facade that
  re-exports the scheduler entrypoint through the existing project module
  surface.
- The move is mechanical: no scheduler behavior was changed, and no scheduler
  internals were split yet.
- The daemon and live GUI source-contract proofs now assert the scheduler lane
  directly while preserving the node-metadata, run-lifecycle, node-contract,
  node-execution, state, checkpoint, approval, output, binding, graph,
  harness-results, execution-results, authority/tooling, memory, package
  output, and PR-create output proofs.
- `runtime.rs` is reduced to 3 lines; the scheduler lane is 617 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeMetadataRuntimeLane === true`,
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler validation lane
refactor:

- Added `apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
  as the dedicated owner for validation-blocked workflow run results.
- `workflow_scheduler_lane.rs` now delegates the `validation.status != "passed"`
  branch to `workflow_scheduler_validation_blocked_result(...)` instead of
  constructing the checkpoint, completion event, final thread, harness artifact
  attachment, completion requirements, and finalized run result inline.
- The split is behavior-preserving: validation failures still emit
  `run_started`, write a blocked checkpoint, emit `run_completed`, attach
  harness run artifacts, compute completion requirements, and persist the
  `WorkflowRunResult`.
- The lane boundary keeps validation-blocked execution graph-addressable for
  the React Flow workflow development environment: the scheduler owns control
  flow, while the validation lane owns the blocked-result contract that can be
  surfaced as a distinct workflow runtime capability.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_validation_lane` and
  `workflow_scheduler_validation_blocked_result(...)` directly, including its
  checkpoint, finalization, harness artifact, completion requirement, and event
  dependencies.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 617 to 567
  lines; the validation lane is 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true` and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler interrupt lane
refactor:

- Added `apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs`
  as the dedicated owner for interrupt/approval pause run finalization.
- `workflow_scheduler_lane.rs` now keeps the scheduling decision
  `(interrupt node or approval preview) && !resume_matches_node`, then delegates
  the paused-result construction to `workflow_scheduler_interrupted_result(...)`.
- The new lane owns interrupt creation, interrupted checkpointing,
  `node_interrupted` and interrupted `run_completed` event emission, interrupted
  node-run evidence, interrupt file persistence, thread persistence, harness
  artifact attachment, completion requirement computation, and final
  `WorkflowRunResult` persistence.
- `workflow_approval_interrupt_lane.rs` remains the low-level approval/interrupt
  payload builder; the scheduler interrupt lane owns orchestration and
  finalization for the paused runtime branch.
- This keeps the pause/resume contract graph-addressable for React Flow
  workflows: approval and human-input pauses now have a distinct runtime lane
  that can be surfaced as a workflow execution capability without hiding the
  lower-level approval preview and interrupt payload helpers.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_interrupt_lane` and
  `workflow_scheduler_interrupted_result(...)` directly, including interrupt
  creation, checkpointing, lifecycle steps, interrupt persistence, thread
  persistence, finalization, harness artifacts, completion requirements, and
  event emission.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 567 to 489
  lines; the interrupt lane is 130 lines; the validation lane remains 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler node execution
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs`
  as the dedicated owner for ready-node execution inside a workflow run.
- `workflow_scheduler_lane.rs` now delegates the non-interrupt ready-node branch
  to `workflow_scheduler_execute_node(...)` and receives an explicit
  `WorkflowSchedulerNodeExecutionFlow` result so the scheduler can continue or
  stop the loop without owning retry and node-run internals.
- The new lane owns node-start events, retry attempts, retry failure evidence,
  `execute_workflow_node(...)` calls, decision branch output selection, state
  updates, completed-node tracking, active-queue expansion, success and failed
  checkpoints, node success/failure events, child workflow completion events,
  output bundle events, and materialized asset events.
- Final run completion remains in `workflow_scheduler_lane.rs` for this slice;
  validation-blocked finalization remains in
  `workflow_scheduler_validation_lane.rs`; interrupt/approval pause finalization
  remains in `workflow_scheduler_interrupt_lane.rs`.
- This keeps per-node execution graph-addressable for React Flow workflows:
  scheduling, paused finalization, validation finalization, and node execution
  are now separate runtime lane capabilities while preserving the existing
  low-level node executor.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_execution_lane` and
  `workflow_scheduler_execute_node(...)` directly, including retry limits, queue
  expansion, checkpointing, lifecycle steps, selected output, state-node logic,
  event emission, child workflow completion, output creation, and asset
  materialization.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 489 to 233
  lines; the node execution lane is 318 lines; the interrupt lane remains 130
  lines; the validation lane remains 88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler finalization lane
refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs`
  as the dedicated owner for post-loop workflow run finalization.
- `workflow_scheduler_lane.rs` now delegates final run completion to
  `workflow_scheduler_finalized_result(...)`; the scheduler owns start,
  validation routing, interrupt routing, ready-node loop orchestration, and
  finalizer dispatch, but no longer owns completion requirement repair,
  terminal checkpoint creation, final thread persistence, harness artifact
  attachment, or result assembly.
- The new lane owns status derivation from blocked/interrupted node state,
  completion requirement checks and missing-output blockers, and final
  checkpoint creation. The following terminal-result consolidation slice moves
  shared event/thread/harness/result assembly behind a common helper while
  preserving this lane as the normal post-loop finalization owner.
- Validation-blocked finalization remains in
  `workflow_scheduler_validation_lane.rs`; interrupt/approval pause
  finalization remains in `workflow_scheduler_interrupt_lane.rs`. This keeps
  each terminal path separately inspectable while extracting the normal
  post-loop completion path.
- This keeps React Flow workflow runs graph-addressable at the scheduling
  boundary: scheduler orchestration, normal finalization, interrupt
  finalization, validation finalization, and node execution are now separate
  runtime lane capabilities.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_finalization_lane`,
  `workflow_scheduler_finalized_result(...)`,
  `workflowSchedulerFinalizationRuntimeLane`, and the finalization lane's
  ownership of completion requirements and final checkpointing.
- `runtime.rs` remains 3 lines; the scheduler lane is reduced from 233 to 157
  lines; the finalization lane is 107 lines; the node execution lane remains
  318 lines; the interrupt lane remains 130 lines; the validation lane remains
  88 lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler terminal result
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs`
  as the shared terminal-result assembly owner for workflow scheduler terminal
  paths.
- The terminal-result lane provides
  `workflow_scheduler_terminal_summary(...)` for consistent
  `WorkflowRunSummary` creation and `workflow_scheduler_terminal_result(...)`
  for `run_completed` event emission, final thread status/checkpoint
  persistence, completion requirement fallback computation, harness artifact
  attachment, and `workflow_finalize_run_result(...)`.
- `workflow_scheduler_finalization_lane.rs`,
  `workflow_scheduler_validation_lane.rs`, and
  `workflow_scheduler_interrupt_lane.rs` now keep their distinct terminal path
  decisions while delegating shared result assembly to the terminal-result
  lane. Normal finalization still owns post-loop status repair and missing
  completion blockers; validation still owns validation-blocked checkpoints;
  interrupt still owns interrupt creation, interrupt persistence, and
  node-interrupted events.
- This also makes validation-blocked terminal runs persist the final thread via
  the same path as normal and interrupted terminal runs.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_terminal_result_lane`,
  `workflow_scheduler_terminal_result(...)`,
  `workflow_scheduler_terminal_summary(...)`,
  `WorkflowSchedulerTerminalResultParts`, and
  `workflowSchedulerTerminalResultRuntimeLane`, while asserting that
  validation and interrupt lanes no longer own direct final-result or harness
  assembly.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane is reduced from 107 to 93 lines; the terminal-result lane is
  93 lines; the interrupt lane is reduced from 130 to 113 lines; the validation
  lane is reduced from 88 to 72 lines; the node execution lane remains 318
  lines.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler node outcome
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs`
  as the shared post-execution success/failure owner for scheduler node runs.
- `workflow_scheduler_node_execution_lane.rs` now owns node-run setup,
  `node_started` emission, retry attempt policy/evidence, and executor calls,
  then delegates the execution result to
  `workflow_scheduler_handle_node_outcome(...)`.
- The outcome lane owns selected-output projection, decision-branch output
  routing, completed-node tracking, interrupted-node filtering, state-node
  reducers, pending write advancement, ready-node expansion, active node set
  refresh, success/failure checkpoints, node-run lifecycle metadata,
  `node_succeeded`/`node_failed` events, child workflow completion events,
  output-node events, and materialized asset events.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_outcome_lane`,
  `workflow_scheduler_handle_node_outcome(...)`,
  `workflowSchedulerNodeOutcomeRuntimeLane`, and the scheduler event/checkpoint
  markers that belong to the outcome lane, while asserting that the execution
  lane no longer owns outcome-only selected-output, state update,
  ready-node/checkpoint, child-output, and materialized-asset behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane is reduced from 318 to 127 lines; the new node
  outcome lane is 238 lines.
- The next file-size pressure is now the outcome lane itself. Its highest-value
  follow-up split is a state update lane that extracts selected-output
  selection, decision-branch handling, state reducers, pending writes, and ready
  node expansion, leaving the outcome lane as the checkpoint/event
  orchestrator.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler node state update
lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs`
  as the success-path state mutation owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates successful node state
  mutation to `workflow_scheduler_apply_node_state_update(...)` and keeps
  checkpoint creation, node-run lifecycle updates, and success/failure event
  emission.
- The state-update lane owns selected-output projection, decision branch
  routing, completed-node tracking, interrupted-node filtering, node output
  recording, state-node reducers, normal output-to-state writes, pending write
  clearing, step advancement, ready-node expansion, and active node set refresh.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_state_update_lane`,
  `workflow_scheduler_apply_node_state_update(...)`,
  `workflowSchedulerNodeStateUpdateRuntimeLane`, and the state mutation markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns selected-output, node-logic reducer, pending-write, or ready-node
  expansion behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node outcome lane is
  reduced from 238 to 164 lines; the new node state-update lane is 106 lines.
- The next file-size pressure is now the 164-line outcome lane. Its
  highest-value follow-up split is a success event lane that extracts
  `node_succeeded`, `child_run_completed`, `output_created`, and
  `asset_materialized` emission, leaving outcome focused on checkpoint
  orchestration and run-record status updates.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler node success
event lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs`
  as the success-path event fanout owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates successful node event
  emission to `workflow_scheduler_emit_node_success_events(...)` and keeps
  checkpoint creation, node-run status/lifecycle updates, and failure-path
  checkpoint/event handling.
- The success-event lane owns `node_succeeded`, `child_run_completed`,
  `output_created`, and `asset_materialized` emission, including child workflow
  status projection and output-bundle materialized asset detection.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_success_event_lane`,
  `workflow_scheduler_emit_node_success_events(...)`,
  `workflowSchedulerNodeSuccessEventRuntimeLane`, and the success-event markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns success-only event names.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node state-update lane
  remains 106 lines; the node outcome lane is reduced from 164 to 105 lines;
  the new node success-event lane is 81 lines.
- The next file-size pressure is no longer outcome-lane size, but outcome-lane
  role clarity. The highest-value follow-up is a small failure outcome lane if
  we want failure checkpointing, blocked-node bookkeeping, node-run error
  mutation, and `node_failed` emission to be independently graph-addressable.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, workflow scheduler node failure
outcome lane refactor:

- Added
  `apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs`
  as the failure-path outcome owner for scheduler node runs.
- `workflow_scheduler_node_outcome_lane.rs` now delegates failed node handling
  to `workflow_scheduler_handle_node_failure_outcome(...)` and acts as the
  success/failure dispatcher plus success checkpoint and run-record
  orchestrator.
- The failure-outcome lane owns blocked-node bookkeeping, failed checkpoint
  creation, node-run error status/lifecycle mutation, node-run recording, and
  `node_failed` event emission.
- The daemon and live GUI source-contract proofs now assert
  `workflow_scheduler_node_failure_outcome_lane`,
  `workflow_scheduler_handle_node_failure_outcome(...)`,
  `workflowSchedulerNodeFailureOutcomeRuntimeLane`, and the failure markers
  that belong to this lane, while asserting that the outcome lane no longer
  owns direct `workflow_push_event` or `node_failed` behavior.
- `runtime.rs` remains 3 lines; the scheduler lane remains 157 lines; the
  finalization lane remains 93 lines; the terminal-result lane remains 93
  lines; the interrupt lane remains 113 lines; the validation lane remains 72
  lines; the node execution lane remains 127 lines; the node state-update lane
  remains 106 lines; the node success-event lane remains 81 lines; the node
  outcome lane is reduced from 105 to 87 lines; the new node failure-outcome
  lane is 55 lines.
- The next pressure is no longer scheduler outcome decomposition. The
  highest-value follow-up is to move laterally into the React Flow proof surface
  and expose the scheduler lanes as explicit workflow capability checks in the
  activation/readiness UI, not only in harness source contracts.

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

Implementation slice completed 2026-05-12, React Flow scheduler lane
readiness UI:

- Added a typed scheduler-lane readiness manifest at
  `packages/agent-ide/src/runtime/workflow-scheduler-lane-readiness.ts`.
  It enumerates the explicit parity-plus lane capabilities:
  `scheduler`, `scheduler.finalization`, `terminalResult`, `nodeExecution`,
  `nodeOutcome`, `nodeStateUpdate`, `nodeSuccessEvent`,
  `nodeFailureOutcome`, `interrupt`, and `validation`.
- `WorkflowValidationResult` now carries `schedulerLaneReadiness`, and
  activation readiness converts missing lane manifest entries into
  `scheduler_lane_capability_missing` execution-readiness blockers.
- Harness activation candidates now include a `scheduler-lanes` gate with a
  `10/10` proof-backed value when every lane is present. The gate evidence
  binds each UI row to the existing harness/source proof keys:
  `workflowSchedulerRuntimeLane`,
  `workflowSchedulerFinalizationRuntimeLane`,
  `workflowSchedulerTerminalResultRuntimeLane`,
  `workflowSchedulerNodeExecutionRuntimeLane`,
  `workflowSchedulerNodeOutcomeRuntimeLane`,
  `workflowSchedulerNodeStateUpdateRuntimeLane`,
  `workflowSchedulerNodeSuccessEventRuntimeLane`,
  `workflowSchedulerNodeFailureOutcomeRuntimeLane`,
  `workflowSchedulerInterruptRuntimeLane`, and
  `workflowSchedulerValidationRuntimeLane`.
- The React Flow workflow readiness rail now shows a dedicated
  `workflow-readiness-scheduler-lanes` section. Each lane row exposes stable
  `data-testid`, `data-readiness`, `data-proof-check`, and
  `data-capability-scope` attributes so live GUI validation can prove the
  scheduler decomposition is visible to operators, not only source-contract
  tests.
- The GUI and daemon contract harnesses now require both the typed readiness
  manifest and the React Flow lane section, while retaining all existing Rust
  scheduler lane source checks.
- `WorkflowRailPanel/core.tsx` remains large at this checkpoint. The next
  intuitive refactor is to extract readiness-panel primitives after the next
  UI slice, so this change adds only a compact section and keeps scheduler
  metadata in the runtime manifest.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- focused runtime import check:
  `node --import tsx - <<'EOF' ... scheduler lane readiness check passed`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- `npm run validate:autopilot-gui-harness`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json`
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - all scheduler runtime lane checks remain true, including failure outcome,
    success event, state update, node outcome, node execution, terminal result,
    finalization, interrupt, validation, and the main scheduler lane.

Implementation slice completed 2026-05-12, React Flow readiness panel
extraction:

- Extracted the `panel === "readiness"` branch from
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx` into
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`.
- Preserved the readiness summary, checklist, blockers, warnings, policy node
  prompts, portable package controls, and scheduler-lane readiness rows without
  changing their stable `data-testid` contracts.
- The extracted panel still renders `workflow-readiness-scheduler-lanes` and
  per-lane `data-proof-check` / `data-capability-scope` attributes, so the
  React Flow scheduler-lane proof remains workflow-addressable after the
  refactor.
- Retargeted daemon and live GUI source-contract checks to require
  `WorkflowReadinessPanel` from the rail core and the scheduler readiness
  markup from `readinessPanel.tsx`.
- Updated the refactor-shape guard so `readinessPanel.tsx` is an owned rail
  module, and refreshed stale core-file checkpoint ceilings to measured
  current baselines. `WorkflowRailPanel/core.tsx` is now 11,427 lines, while
  the extracted readiness panel is 444 lines.

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs && node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json`
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`.

Implementation slice completed 2026-05-12, React Flow readiness model
extraction:

- Extracted readiness checklist, blocker/warning aggregation, policy-required
  node ids, scheduler-lane ready counts, and attention ordering into the pure
  runtime helper
  `packages/agent-ide/src/runtime/workflow-readiness-model.ts`.
- `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`
  is now a presentational React Flow rail panel over `workflowReadinessModel(...)`
  while preserving stable readiness summary, checklist, blocker, warning,
  policy, portable package, and scheduler-lane DOM contracts.
- Added
  `packages/agent-ide/src/runtime/workflow-readiness-model.test.ts` to lock the
  runtime model behavior for manifest-backed scheduler readiness, missing lane
  blockers, blocker-before-warning attention ordering, replay-fixture warning
  readiness, and incoming model-class edge bindings.
- Retargeted the daemon and live GUI source-contract checks so scheduler-lane
  activation readiness must be present in both the runtime model and the React
  Flow panel. The live proof source refs now include
  `workflow-readiness-model.ts` alongside `readinessPanel.tsx`.
- Updated the refactor-shape guard so the extracted runtime model is an owned
  implementation module. `WorkflowRailPanel/core.tsx` remains 11,427 lines,
  `readinessPanel.tsx` is reduced from 444 to 314 lines, and the readiness
  model is 226 lines with a 232-line focused test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-readiness-model.ts`.

Implementation slice completed 2026-05-12, React Flow unit-test readiness
model extraction:

- Extracted unit-test search, coverage accounting, uncovered-node detection,
  status rollups, latest-result lookup, target-node binding, and row status
  projection into the pure runtime helper
  `packages/agent-ide/src/runtime/workflow-test-readiness-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx`
  as the presentational React Flow rail surface for the existing unit-test
  summary, search, result rows, target-node links, and uncovered-node prompts.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "unit_tests"` branch
  to `WorkflowUnitTestsPanel` and reuses the model's `coveredNodeIds` for the
  readiness panel, so evaluation coverage becomes a reusable workflow-development
  model instead of rail-only inline logic.
- Added
  `packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts` to lock
  coverage counts, status counts, search by assertion/status/target id, latest
  result row projection, and uncovered-node reporting.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  unit-test readiness must exist in both the runtime model and the React Flow
  panel. The live rollback proof now includes `workflowUnitTestReadinessModelUi`
  and source refs for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 11,427 to 11,310 lines. The new
  unit-test panel is 105 lines, and the test-readiness model is 110 lines with a
  190-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-test-readiness-model.ts`.

Implementation slice completed 2026-05-12, React Flow run-history model
extraction:

- Extracted run search/filtering, status rollups, visible row selection,
  selected-run binding, default comparison target, comparison projection,
  interrupt preview, timeline fallback, and harness attempt/shadow comparison
  projection into
  `packages/agent-ide/src/runtime/workflow-run-history-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx`
  as the presentational React Flow rail surface for run filters, run cards,
  comparison details, interrupt preview, attempt inspection, harness timelines,
  shadow comparisons, event timeline, checkpoints, and workbench dogfood
  summaries.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "runs"` branch to
  `WorkflowRunsPanel` over `workflowRunHistoryModel(...)`, keeping durable run
  history and replay/inspection state reusable by workflow authoring surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-run-history-model.test.ts` to lock
  status/search filtering, selected/compare row flags, selected-run timeline
  binding, comparison generation, ambient-event fallback, interrupt preview,
  and harness attempt/shadow comparison projection.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so run
  history must exist in both the runtime model and the React Flow panel. The
  live rollback proof now includes `workflowRunHistoryModelUi` and source refs
  for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 11,310 to 10,939 lines. The new
  runs panel is 424 lines, and the run-history model is 128 lines with a
  295-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-run-history-model.ts`.

Implementation slice completed 2026-05-12, React Flow search model
extraction:

- Extracted rail-search normalization, result counting, result-kind grouping,
  visible result slicing, hidden-result accounting, actionability flags, and
  empty-state copy into
  `packages/agent-ide/src/runtime/workflow-rail-search-model.ts`.
- Added
  `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx`
  as the presentational React Flow rail surface for search input, indexed
  workflow counts, result actions, result metadata, and filtered empty states.
- `WorkflowRailPanel/core.tsx` now delegates the `panel === "search"` branch to
  `WorkflowSearchPanel` over `workflowRailSearchModel(...)`, keeping workflow
  discovery/navigation reusable by chat/autopilot workflow creation and graph
  authoring surfaces.
- Added
  `packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts` to lock
  indexed counts, normalization, node/test/output filtering, result-kind
  grouping, visible slicing, test target-node actions, and empty filtered
  states.
- Retargeted daemon, refactor-shape, and live GUI source-contract checks so
  rail search must exist in both the runtime model and React Flow panel. The
  live rollback proof now includes `workflowRailSearchModelUi` and source refs
  for both files.
- `WorkflowRailPanel/core.tsx` is reduced from 10,939 to 10,903 lines. The new
  search panel is 63 lines, and the rail-search model is 109 lines with a
  177-line focused model test.

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-rail-search-model.ts`.

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
