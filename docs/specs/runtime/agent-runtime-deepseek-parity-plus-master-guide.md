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
- `docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md`
- `docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md`
- `docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md`

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

## Current Implementation State

The strategic target and gap inventory remain in this guide. Completed slice
details and repeated proof output now live in companion ledgers:

- `docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md`
- `docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md`

Maintainers should keep this guide focused on target architecture, parity gaps,
roadmap decisions, and the immediate tactical queue. New completed-slice detail
should go into the implementation log, with proof paths summarized in the
validation ledger.

Strategic snapshot as of 2026-05-13:

- The live bridge foundation is now usable for parity work: TTI schemas,
  daemon event-store replay, Rust `RuntimeAgentService` bridge execution,
  KernelEvent mapping, SDK `Thread`/`Turn` wrappers, CLI `agent stream`, React
  Flow read-only event projection, a thin daemon-backed `ioi agent tui` shell,
  TUI/workflow deep-link descriptors, a daemon-backed line-mode TUI loop,
  React Flow/TUI operator-control equivalence, durable TUI control-state
  projection rows, approval/mode-status rows, and the first live controls
  (`interrupt`, `steer`, `compact`, `fork`, approval accept/reject, restore
  list/preview/apply) all have cross-surface proofs.
- React Flow workflow-authoring can now create those same runtime-control
  requests with preserved graph/node identity through daemon SSE, SDK events,
  CLI stream output, and the read-only React Flow projection.
- Model routing, memory, doctor/config, skills, hooks, GitHub/PR, task/job
  records, package/import execution, localization/accessibility, promotion, and
  default dispatch have validated foundation slices in the companion ledgers.
- React Flow settings harness refactors are now maintenance work. They should
  continue only when they unblock a named parity-plus capability or prevent an
  active workflow-development surface from becoming unmaintainable.

Most recent completed implementation slice:

- 2026-05-13: P0-C executable diagnostics repair `repair_retry`
- Evidence:
  `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json`
- Trace detail:
  `docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md`
  and
  `docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md`

### Active Parity Gap Ledger

This table is the guide-level source of truth for choosing the next slice.
Completed-slice history belongs in the companion ledgers.

| Rank | Gap | Current State | Next Proof Needed | React Flow Requirement |
| --- | --- | --- | --- | --- |
| P0-A | Terminal coding-agent TUI | `ioi agent tui` can start/select/resume a daemon thread, submit one message, render canonical events, replay by cursor, expose event-row deep links that match React Flow run-inspector reopen descriptors, run an opt-in line-mode loop for `/resume`, `/events`, `/approvals`, `/approve`, `/reject`, `/interrupt`, `/steer`, `/status`, `/diff`, `/inspect`, `/patch`, `/patch-dry-run`, `/test`, `/diagnostics`, `/artifact`, `/retrieve`, `/restore`, and `/quit`, prove React Flow-authored interrupt/steer/restore nodes share the same event contract as TUI slash commands, and emit command history/current-turn/last-cursor/validation-error/mode-status/approval/coding-tool/restore rows that React Flow can inspect. | Add the next keyboard-first TUI surface only when it is backed by a named runtime contract. | TUI panels should stay daemon-owned, event-backed, and mirrored as React Flow run-inspector rows rather than becoming canvas-local state. |
| P0-B | Coding tool pack | `workspace.status`, `git.diff`, `file.inspect`, `file.apply_patch`, `test.run`, `lsp.diagnostics`, `artifact.read`, and `tool.retrieve_result` are daemon-owned coding-pack tools exposed through `/v1/tools?pack=coding` and `/v1/threads/{thread_id}/tools/{tool_id}/invoke`, with SDK list/invoke methods, CLI `agent tools coding/run`, TUI `/status` `/diff` `/inspect` `/patch` `/patch-dry-run` `/test` `/diagnostics` `/artifact` `/retrieve`, receipt-backed `tool.completed` events, range-aware test-output spillover artifacts, React Flow projection rows, and `coding_tool_pack` workflow binding controls for filesystem read/write, dry-run, diagnostics mode/default command, restore policy, restore conflict policy, diagnostics repair default, operator-override approval, artifact retrieval, allowed paths, command ids, and timeouts. `file.apply_patch` now reports changed-file existence/size/mtime metadata and emits workspace snapshot ids, artifacts, receipts, and rollback refs for applied mutations. `lsp.diagnostics` defaults to `auto`, resolves TypeScript files with a nearest-`tsconfig.json` project check when local `tsc` is available, and emits degraded/fallback receipts when it must fall back. | Execute the last diagnostics repair decision, `operator_override`, through the same coding-pack contracts. | Tool-pack nodes can enable/disable git/test/diagnostics/artifact/filesystem capabilities independently and compile those settings into daemon tool invocation requests; applied patch rows now link to workspace snapshot evidence and workflow-authored restore/repair policy. |
| P0-C | Post-edit LSP diagnostics | Mutating `file.apply_patch` now auto-runs configured diagnostics for changed files, records `runtime_auto` diagnostic events, injects compact findings into the next local or runtime-bridge turn, emits a receipt-backed `lsp.diagnostics.injected` event, and projects the injection through SDK and React Flow. React Flow coding-pack controls expose `advisory`, `blocking`, and `skip` modes plus default diagnostic command; nested `toolPack.coding.*` config is honored by daemon invocation. `blocking` mode now stops model continuation before a local or runtime-bridge turn, creates a blocked turn/run with no assistant delta, emits a receipt-backed `policy.blocked` diagnostics gate, and binds candidate workspace snapshot refs into a workflow-configurable rollback/repair policy with `repair_retry`, `restore_preview`, `restore_apply`, and `operator_override` decision refs visible to SDK and React Flow. Default `auto` diagnostics now carry requested/resolved command ids, backend, backend status/reason, project context, TypeScript project findings, degraded fallback receipts, rollback repair context, restore policy, conflict policy, preferred repair default, and override approval requirement. The `repair_retry`, `restore_preview`, and `restore_apply` repair decisions are now executable through a daemon endpoint and SDK method, emit `diagnostics.repair_decision.executed`, preserve React Flow graph/node identity, and either create a diagnostics-injected retry turn or delegate to the existing restore contracts. | Add action execution for `operator_override`. | `LspDiagnosticsNode` and coding-pack diagnostics controls change runtime warning/error injection behavior and surface injected findings, backend metadata, degraded receipts, blocking gates, rollback refs, repair retries, restore previews, restore applies, and repair decision executions as workflow-addressable rows. |
| P0-D | Workspace rollback snapshots | Applied `file.apply_patch` calls now create first-class, receipt-backed, content-backed `workspace.snapshot.created` records for size-limited UTF-8 touched files, store before/after content in a redacted snapshot artifact, expose snapshot listing and SDK helpers, support daemon-owned `restore-preview` with drift/conflict checks, and support policy-gated `restore-apply` with explicit approval, conflict override policy, receipts, artifacts, rollback refs, SDK results, React Flow `restore_gate` rows, and diagnostics rollback/repair gate integration without touching user `.git`. React Flow coding-pack controls can configure restore authority, conflict behavior, and repair policy defaults, first-class `RuntimeRollbackSnapshotNode`/`RuntimeRestoreGateNode` definitions compile restore requests across the editor registry, local workflow execution lane, project templates, generated action schemas, and source contracts, and TUI `/restore` lists snapshots, previews restore operations, applies snapshots only with `--approve`, and replays restore events for React Flow projection. Diagnostics repair `restore_preview` and `restore_apply` now reuse the same restore endpoints and projection contracts. | Keep restore repair execution aligned while wiring `operator_override`. | Snapshot, restore-preview, and restore-apply rows are configurable rollback/restore workflow inputs; `RollbackSnapshotNode`, `RestoreGateNode`, TUI restore commands, and diagnostics repair decisions must remain projections of the same daemon restore endpoints. |
| P1-A | Subagent runtime parity | Delegation patterns exist, but the full role-aware lifecycle and output contract are not productized. | Spawn, wait, send input, cancel, resume, and validate output contract for parallel child agents. | Subagent pool/role/join nodes enforce concurrency, budget, and merge policy. |
| P1-B | MCP manager parity | MCP containment exists, but manager UX and self-hosted MCP modes remain incomplete. | Import, validate, enable/disable, invoke, and serve MCP under IOI containment. | MCP server/tool/resource nodes compile into governed runtime config. |
| P1-C | Modes, trust, approvals | Rich policy internals exist, but product-level Plan/Agent/YOLO/review modes need one stable contract. | Mode changes are evented and enforced by runtime policy even when UI config is permissive. | Graph-level mode selector and node approval overrides compile into one approval manifest. |
| P1-D | Usage, cost, context telemetry | Usage fragments exist, but product-grade per-turn/session cost and context pressure are not unified. | Live usage/context events aggregate through API, SDK, CLI/TUI, and workflow budget nodes. | Usage and budget nodes can simulate and enforce workflow caps. |

### Immediate Tactical Queue

1. Add action execution for the remaining diagnostics repair decision:
   `operator_override`. Use the repair retry and restore repair executors as the
   reference pattern for policy refs, receipts, and React Flow identity.
2. If another keyboard-first TUI gap appears while wiring repair actions, keep it
   daemon-owned and event-backed like the approval/mode-status panel.
3. Continue settings harness cleanup only as maintenance, gated by a concrete
   parity slice dependency or a source-contract bloat guard failure.
4. Keep this guide strategic. Put completed slice narratives in the
   implementation log and proof commands/evidence paths in the validation
   ledger.

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
  `/v1/threads/{id}/approvals/{approval_id}/decision`,
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
- `artifact__read`;
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

Current live P0-B tool ids:

- `workspace.status`;
- `git.diff`;
- `file.inspect`;
- `file.apply_patch`;
- `test.run`;
- `lsp.diagnostics`;
- `artifact.read`;
- `tool.retrieve_result`.

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

Add per-turn workspace snapshots and restore controls that do not mutate user
`.git`.

Runtime work:

- Add `WorkspaceSnapshotService`.
- Snapshot before and after every mutating turn in Agent/YOLO modes. The current
  live baseline records content-backed pre/post touched-file snapshots for
  applied `file.apply_patch` calls when files fit the capture policy.
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
- Support restore preview and restore apply over captured snapshot content. The
  current live baseline supports restore preview with current-workspace drift
  detection and policy-gated restore apply that requires explicit approval and
  blocks conflicts unless the request carries an override policy.
- Respect `.gitignore`, path policy, file size limits, and redaction rules.

Daemon/API work:

- `GET /v1/threads/{id}/snapshots`;
- `GET /v1/threads/{id}/snapshots/{snapshot_id}/diff`;
- `POST /v1/threads/{id}/snapshots/{snapshot_id}/restore-preview`;
- `POST /v1/threads/{id}/snapshots/{snapshot_id}/restore-apply`.

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
| Coding tools | coding tool pack | `/v1/tools?pack=coding`, `/v1/threads/{thread_id}/tools/{tool_id}/invoke` | `listTools({ pack })`, `invokeThreadTool` | `agent tools coding/run`, TUI `/status` `/diff` `/inspect` `/patch` `/patch-dry-run` `/test` `/diagnostics` `/artifact` `/retrieve` | `coding_tool_pack` binding and projected coding-tool/artifact rows |
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

After the first coding tool-pack slice, update runtime prompts to prefer:

- structured file/search/git/test/diagnostic tools over shell;
- `file__apply_patch` for multi-hunk code edits;
- `tool__retrieve_result` and `artifact__read` for large outputs;
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

## Next Implementation Slices

The live bridge contract is now locked in
`docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md`, and the
first live runtime controls are available across daemon SSE, SDK, CLI stream,
and React Flow workflow-originated requests. The next slices should therefore
exercise the bridge through user-visible DeepSeek parity surfaces instead of
adding more infrastructure by default.

Next runtime implementation sequence:

1. Execute the remaining diagnostics repair decision from the graph policy:
   `operator_override`.
2. Move from the thin TUI shell toward the full terminal coding-agent surface:
   jobs, MCP, memory, cost/context, subagents, and workflow graph
   affordances.

React Flow cleanup remains allowed, but it is now a support track. A cleanup
slice should cite the parity gap it unblocks or the source-contract guard it
keeps healthy before it displaces a P0 parity slice.
