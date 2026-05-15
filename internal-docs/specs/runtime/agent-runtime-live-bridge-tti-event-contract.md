# Agent Runtime Live Bridge TTI Event Contract

Status: P0 contract-lock spec
Created: 2026-05-12
Origin: extracted from the completed Agent Runtime DeepSeek TUI parity-plus
planning effort; this file remains as the durable live-bridge contract.

## Purpose

This spec locks the first production contract for the live runtime API bridge and
durable thread/turn/item model. It closes the highest-risk DeepSeek parity gap:
daemon runs must be live runtime-backed, replayable, and resumable instead of
synthetic run projections.

The contract is intentionally a bridge, not a replacement runtime. IOI keeps
`RuntimeAgentService` and `AgentState` as the canonical execution substrate, and
adds a public, replayable TTI projection over the same runtime truth.

## Source Of Truth

Canonical runtime owners:

- `crates/services/src/agentic/runtime/README.md`
- `crates/services/src/agentic/runtime/types.rs`
- `crates/services/src/agentic/runtime/substrate.rs`
- `crates/types/src/app/events.rs`
- `crates/types/src/app/runtime_contracts.rs`
- `crates/types/src/app/runtime/thread_turn_item.rs`

Projection and client owners:

- `packages/runtime-daemon/src/index.mjs`
- `packages/agent-sdk/src/messages.ts`
- `packages/agent-sdk/src/substrate-client.ts`
- `packages/agent-ide/src/runtime/*`

Existing state and event vocabulary:

- `AgentState` remains the persisted session record.
- `KernelEvent` remains the canonical low-level runtime event/receipt stream.
- `ActionRequest` remains the canonical action intent shape before drivers.
- `AgentRuntimeEvent` remains the typed runtime substrate event projection.
- `RuntimeTraceBundle` and `IOISDKMessage` remain SDK-facing projections until
  the new TTI SDK wrappers consume the locked record types directly.

Implementation status:

- 2026-05-12: schema snapshot slice is locked in Rust and TypeScript for
  `RuntimeThreadRecord`, `RuntimeTurnRecord`, `RuntimeItemRecord`, and
  `RuntimeEventEnvelope`.
- The modular Rust owner is
  `crates/types/src/app/runtime/thread_turn_item.rs`; the compatibility export
  remains `crates/types/src/app/runtime_contracts.rs`.
- The SDK wire snapshot lives in `packages/agent-sdk/src/messages.ts` and is
  exported from the SDK root.
- `scripts/lib/live-bridge-tti-schema-contract.test.mjs` compares schema
  literals, enum literal arrays, required record fields, and export surfaces.
- 2026-05-12: daemon event-store slice persists `RuntimeEventEnvelope` rows as
  append-only JSONL streams, assigns monotonic `seq`, returns the original row
  for duplicate idempotency keys, and returns `event_cursor_out_of_range` for
  future cursors.
- 2026-05-12: daemon replay alias slice resolves `Last-Event-ID` as either
  sequence or `event_id`, exposes `/v1/threads/{id}/events/stream`, maps
  `/v1/runs/{id}/events` and `/v1/runs/{id}/replay` to the owning turn event
  range, and keeps SDK `IOISDKMessage` compatibility by normalizing stored
  `RuntimeEventEnvelope` rows at the client edge.
- 2026-05-12: daemon `RuntimeApiBridge` boundary slice adds explicit
  `runtime_profile=runtime_service` routing, fails closed without a configured
  bridge, persists injected bridge `thread.started`, `turn.started`, and
  `turn.completed` rows with `fixture_profile: null`, and blocks silent fixture
  fallback for runtime-service threads.
- 2026-05-12: daemon command adapter slice locks
  `ioi.runtime.bridge.command.v1` as the stdin/stdout process protocol behind
  `RuntimeApiBridge`.
- 2026-05-12: Rust bridge executable slice adds
  `crates/node/src/bin/ioi-runtime-bridge.rs`, which calls durable
  `RuntimeAgentService` `start@v1`, `post_message@v1`, and `step@v1`
  operations against `RedbFlatStore` and `MemoryRuntime` while returning
  bridge-ready TTI events.
- 2026-05-12: daemon Rust bridge contract wires the env command adapter to the
  real `ioi-runtime-bridge` executable, then proves canonical thread/turn/run
  event replay over Rust-owned runtime-service events with
  `fixture_profile: null`.
- 2026-05-12: KernelEvent mapper slice adds
  `crates/node/src/runtime_bridge_events.rs`, drains the Rust
  `RuntimeAgentService` broadcast channel, maps `AgentStep`, `AgentThought`,
  `FirewallInterception`, `AgentActionResult`, `WorkloadReceipt`, and
  `RoutingReceipt` into bridge-ready TTI events, and proves a live
  `KernelEvent::AgentActionResult` row replays through the daemon.

## Non Goals

- Do not build a second runtime loop in the daemon.
- Do not let React Flow store thread or event truth.
- Do not make `/v1/runs` the canonical model. Runs remain compatibility aliases
  over thread/turn records.
- Do not expose fixture/synthetic run builders on production endpoints without
  an explicit fixture profile and visible fixture metadata.
- Do not block implementation on the full TUI. TUI follows once the event
  stream contract is real.

## RuntimeApiBridge Boundary

`RuntimeApiBridge` is the seam between public clients and `RuntimeAgentService`.
It must own orchestration only:

- submit `start`, `post_message`, `step`, `resume`, `pause`, `cancel`,
  `interrupt`, and approval decisions into the runtime service;
- subscribe to `KernelEvent` and runtime substrate events for the same session;
- append normalized public events into an event store;
- project thread, turn, and item records from `AgentState` plus appended events;
- expose daemon cursors and SSE without creating synthetic runtime facts.

The bridge must not:

- execute tools directly;
- mutate workflow canvas state;
- fabricate successful turns when the runtime service is unavailable;
- swallow approval, policy, PII, or wallet authority receipts;
- reorder events after append.

## Command Bridge Protocol

The local runtime-service profile may bind `RuntimeApiBridge` to an external
process using `ioi.runtime.bridge.command.v1`.

Request shape on stdin:

- `schema_version`: literal `ioi.runtime.bridge.command.v1`
- `bridge_id`
- `operation`: `start_thread | submit_turn`
- `input`: the daemon bridge input object

Response shape on stdout:

- success: `{ "ok": true, "result": <RuntimeApiBridge result> }`
- failure: `{ "ok": false, "error": { "code": "...", "message": "..." } }`

The Rust owner is `ioi-runtime-bridge`. It must:

- own durable `RuntimeAgentService` execution rather than fixture projection;
- persist state across separate command invocations;
- return `fixture_profile: null` for runtime-service events;
- surface unavailable inference, policy, approval, and runtime blockers as
  explicit bridge statuses/events instead of fabricated success.

## Stable Records

### RuntimeThreadRecord

`RuntimeThreadRecord` is the public durable conversation/workspace container.

Required fields:

- `schema_version`: literal `ioi.runtime.thread.v1`
- `thread_id`: stable public id, not raw binary session bytes
- `session_id`: hex runtime `AgentState.session_id`
- `agent_id`
- `workspace_root`
- `title`
- `mode`: `plan | agent | yolo | custom`
- `approval_mode`
- `trust_profile`
- `model_route`
- `status`: `active | idle | waiting | interrupted | completed | failed | archived`
- `latest_turn_id`
- `latest_seq`
- `event_stream_id`
- `workflow_graph_id`
- `harness_binding_id`
- `agentgres_projection_ref`
- `created_at`
- `updated_at`
- `archived_at`
- `fixture_profile`: `null` in production-backed threads

Invariants:

- `thread_id` is stable across daemon restart.
- `session_id` points to exactly one active or archived `AgentState`.
- `latest_seq` equals the highest committed event sequence for the thread.
- `fixture_profile` must be non-null for synthetic/dev threads and visible in
  daemon, SDK, CLI/TUI, and React Flow projections.

### RuntimeTurnRecord

`RuntimeTurnRecord` is the public lifecycle for one user request, resume, fork,
or system-driven runtime continuation.

Required fields:

- `schema_version`: literal `ioi.runtime.turn.v1`
- `turn_id`
- `thread_id`
- `parent_turn_id`
- `request_id`
- `status`: `queued | running | waiting_for_approval | waiting_for_input |
  interrupted | completed | failed | canceled`
- `input_item_ids`
- `output_item_ids`
- `seq_start`
- `seq_end`
- `started_at`
- `completed_at`
- `mode`
- `approval_mode`
- `model_route_decision_id`
- `usage`
- `stop_reason`
- `error`
- `rollback_snapshot_id`
- `quality_ledger_ref`
- `workflow_execution_ref`
- `fixture_profile`

Invariants:

- Every turn belongs to exactly one thread.
- `seq_start` is the first event appended for that turn.
- `seq_end` is null until the turn reaches a terminal status.
- Runtime waits for approval/input are statuses, not hidden client states.
- Interrupt/cancel requests append events even when the runtime had already
  reached a terminal status.

### RuntimeItemRecord

`RuntimeItemRecord` is the durable transcript/event item that clients render.

Required fields:

- `schema_version`: literal `ioi.runtime.item.v1`
- `item_id`
- `thread_id`
- `turn_id`
- `kind`
- `status`
- `seq_start`
- `seq_end`
- `actor`: `user | assistant | tool | runtime | policy | system`
- `summary`
- `content_ref`
- `tool_name`
- `component_kind`
- `workflow_node_id`
- `receipt_refs`
- `artifact_refs`
- `approval_id`
- `policy_decision_id`
- `rollback_snapshot_id`
- `redaction_profile`
- `payload_schema_version`

Required item kinds:

- `user_message`
- `agent_message`
- `reasoning_delta`
- `tool_call`
- `tool_result`
- `file_change`
- `command_execution`
- `approval_required`
- `approval_decision`
- `context_compaction`
- `lsp_diagnostics`
- `memory_update`
- `subagent_event`
- `rollback_snapshot`
- `status`
- `error`

Invariants:

- Every side-effecting item has at least one `receipt_ref`, or an explicit
  `no_receipt_reason` in its payload.
- Large payloads go to `content_ref`/artifact refs; event rows keep summaries.
- Redacted items preserve ids, seq, kind, and receipt refs even when content is
  withheld.

## RuntimeEventEnvelope

Every public stream row uses `RuntimeEventEnvelope`.

Required fields:

- `schema_version`: literal `ioi.runtime.event.v1`
- `event_id`
- `event_stream_id`
- `thread_id`
- `turn_id`
- `item_id`
- `seq`: monotonic positive integer within `event_stream_id`
- `parent_seq`
- `idempotency_key`
- `source`: `runtime_service | daemon_bridge | sdk_client | cli_tui |
  react_flow | fixture`
- `source_event_kind`: `KernelEvent::<variant>`, `AgentRuntimeEvent`, or
  bridge-local event kind
- `event_kind`
- `status`
- `actor`
- `created_at`
- `workspace_root`
- `workflow_graph_id`
- `workflow_node_id`
- `component_kind`
- `tool_call_id`
- `approval_id`
- `artifact_refs`
- `receipt_refs`
- `policy_decision_refs`
- `rollback_refs`
- `payload_schema_version`
- `payload_ref`
- `payload`
- `redaction_profile`
- `fixture_profile`

Sequence invariants:

- `seq` is assigned only by the append-only event store.
- `seq` never changes after append.
- No two events in one `event_stream_id` share a `seq`.
- Events may arrive from runtime broadcast channels out of wall-clock order, but
  clients render append order by `seq`.
- `created_at` records observed event time; `seq` is the replay authority.
- A bridge restart must resume from the stored high-water mark before accepting
  new turn writes.

Idempotency invariants:

- `idempotency_key` is stable for retried bridge writes of the same source
  event.
- Duplicate idempotency keys return the first appended event.
- Client-submitted turns, approvals, interrupts, and compactions must include
  client request ids that flow into `idempotency_key`.

## Source Event Mapping

Minimum mapping for the first live bridge slice:

| Source | Public event kind | Item kind | Required refs |
| --- | --- | --- | --- |
| `AgentState` start | `thread.started` | `status` | session id |
| user turn create | `turn.created` | `user_message` | request id |
| `KernelEvent::AgentThought` | `reasoning.delta` | `reasoning_delta` | session id |
| `KernelEvent::AgentStep` | `turn.step` | `status` or `agent_message` | step index |
| `KernelEvent::FirewallInterception` | `approval.required` or `policy.blocked` | `approval_required` or `error` | request hash |
| `KernelEvent::AgentActionResult` | `tool.completed` or `tool.failed` | `tool_result` | tool name, step index |
| `KernelEvent::WorkloadReceipt` | `receipt.emitted` | source item | receipt id |
| `KernelEvent::RoutingReceipt` | `model.route_decision` or `tool.route_decision` | `status` | route receipt |
| `AgentRuntimeEvent` | `runtime.substrate_event` | source item | event id |
| bridge interrupt | `turn.interrupt_requested` | `status` | request id |
| bridge compaction | `context.compacted` | `context_compaction` | compaction artifact |

Later slices must expand this table for MCP, memory, LSP, subagents, rollback,
workspace snapshots, GitHub/PR, and workflow activation events.

## Daemon API Contract

Canonical endpoints:

- `POST /v1/threads`
- `GET /v1/threads`
- `GET /v1/threads/{thread_id}`
- `POST /v1/threads/{thread_id}/resume`
- `POST /v1/threads/{thread_id}/fork`
- `POST /v1/threads/{thread_id}/archive`
- `POST /v1/threads/{thread_id}/turns`
- `GET /v1/threads/{thread_id}/turns`
- `GET /v1/threads/{thread_id}/turns/{turn_id}`
- `POST /v1/threads/{thread_id}/turns/{turn_id}/steer`
- `POST /v1/threads/{thread_id}/turns/{turn_id}/interrupt`
- `POST /v1/threads/{thread_id}/turns/{turn_id}/cancel`
- `POST /v1/threads/{thread_id}/turns/{turn_id}/compact`
- `GET /v1/threads/{thread_id}/items`
- `GET /v1/threads/{thread_id}/events?since_seq=N`
- `GET /v1/threads/{thread_id}/events/stream?since_seq=N`

Compatibility aliases:

- `/v1/agents` maps to thread-capable agent profiles.
- `/v1/runs` maps to turn records.
- `/v1/runs/{run_id}/events` maps to the owning turn event range.
- `/v1/runs/{run_id}/trace` maps to a trace bundle derived from TTI/events.

Production behavior:

- `POST /v1/threads` must fail closed if `RuntimeApiBridge` cannot reach the
  runtime service.
- `POST /v1/threads/{thread_id}/turns` must append a `turn.created` event only
  after runtime submission is accepted.
- Event endpoints may serve persisted history while the runtime is offline, but
  must mark live writes unavailable.

Fixture behavior:

- Fixture/dev profiles require `runtime_profile=fixture` or an equivalent
  explicit daemon configuration.
- Fixture threads include `fixture_profile` on thread, turn, item, and event
  projections.
- Fixture events use `source: "fixture"`.
- SDK, CLI/TUI, and React Flow must visibly mark fixture-backed streams.

## SSE Replay Contract

`GET /v1/threads/{thread_id}/events/stream` returns `text/event-stream`.

Cursor inputs:

- `since_seq=N` starts after sequence `N`.
- `Last-Event-ID` may carry either `seq` or `event_id`.
- If both are present, `since_seq` wins and the response includes a warning
  field in the first event comment or metadata row.

SSE row shape:

```text
id: 42
event: runtime.event
data: {"schema_version":"ioi.runtime.event.v1","seq":42,...}
```

Replay rules:

- `since_seq=0` replays the full stream.
- Reconnect from `Last-Event-ID: 42` starts at `43`.
- Unknown future cursors return `409` with `latest_seq`.
- Archived threads remain replayable.
- Redaction is applied at read time, but redacted replay must preserve event
  count and sequence.

## SDK Contract

Add durable wrappers over the same stream:

- `Thread`
- `Turn`
- `RuntimeItem`
- `RuntimeEvent`

Required methods:

- `agent.threads.create()`
- `agent.threads.list()`
- `agent.threads.get(threadId)`
- `thread.turns.create(input)`
- `thread.turns.list()`
- `thread.events({ sinceSeq })`
- `thread.stream({ sinceSeq, lastEventId })`
- `thread.resume()`
- `thread.fork()`
- `turn.steer(input)`
- `turn.interrupt(reason)`
- `turn.cancel(reason)`
- `turn.compact(options)`

Compatibility:

- `Agent.send()` remains an ergonomic wrapper around
  `thread.turns.create()`.
- `Run.events()` remains an alias over the owning turn event range.
- `RuntimeTraceBundle.events` can remain `IOISDKMessage[]` during migration,
  but must carry enough ids to reconstruct `RuntimeEventEnvelope`.

## CLI/TUI Contract

CLI commands:

- `ioi agent thread list`
- `ioi agent thread show <thread_id>`
- `ioi agent thread resume <thread_id>`
- `ioi agent thread fork <thread_id>`
- `ioi agent send --thread <thread_id>`
- `ioi agent events --thread <thread_id> --since-seq <n>`
- `ioi agent stream --thread <thread_id> --since-seq <n>`
- `ioi agent interrupt --turn <turn_id>`
- `ioi agent compact --turn <turn_id>`

TUI requirements:

- The TUI consumes `/v1/threads/*` and SSE only.
- The TUI never writes private daemon state directly.
- Approval and interrupt controls submit API requests and wait for stream
  confirmation.
- Closing and reopening the TUI resumes from the last stored event cursor.

## React Flow Contract

Node categories:

- `RuntimeThreadNode`
- `RuntimeTurnNode`
- `RuntimeEventStreamNode`
- `RuntimeItemTimelineNode`
- `InterruptGateNode`
- `SteerInputNode`
- `CompactionNode`
- `RuntimeBridgeHealthNode`

Inspector fields:

- thread id
- turn id
- status
- latest seq
- event stream id
- replay cursor
- model route
- mode
- workspace root
- policy posture
- fixture profile
- linked artifacts
- receipt refs
- workflow node ids

Graph rules:

- React Flow stores graph configuration, not event truth.
- Runtime nodes display daemon projections from TTI/events.
- A graph activation may create a runtime thread, but the thread remains owned
  by the runtime bridge.
- Deep links must include thread id plus seq, turn id, item id, or receipt ref.

## Persistence Contract

The first implementation may use the daemon state store, but must preserve an
Agentgres-compatible shape:

- append-only event table keyed by `(event_stream_id, seq)`;
- unique `(event_stream_id, idempotency_key)`;
- thread table keyed by `thread_id`;
- turn table keyed by `turn_id`;
- item table keyed by `item_id`;
- secondary indexes for `session_id`, `workflow_graph_id`, `workflow_node_id`,
  `receipt_refs`, and `artifact_refs`.

Persisted records must survive daemon restart and be replayable before runtime
service reconnection.

## Error Semantics

Required API errors:

- `runtime_bridge_unavailable`
- `thread_not_found`
- `turn_not_found`
- `event_cursor_out_of_range`
- `event_stream_gap_detected`
- `runtime_submission_rejected`
- `approval_required`
- `turn_already_terminal`
- `fixture_profile_required`
- `production_runtime_required`

Every error response includes:

- `code`
- `message`
- `request_id`
- `thread_id` when known
- `turn_id` when known
- `latest_seq` when cursor-related
- `receipt_refs` when policy or approval related

## Contract Tests

Minimum contract-lock tests before implementation:

- Rust and TypeScript schema snapshots agree on thread, turn, item, and event
  records.
- `RuntimeEventEnvelope.seq` is monotonic under duplicate source events.
- duplicate idempotency keys return the first event.
- production thread creation fails when the bridge is unavailable.
- fixture thread creation is impossible without explicit fixture profile.
- `since_seq=0` replay reconstructs item order.
- `Last-Event-ID` reconnect resumes at the next sequence.
- `/v1/runs/{id}/events` returns the same event ids as the owning turn.
- React Flow runtime thread/turn/event nodes can render from event replay only.

## First Implementation Slices

1. Add shared schema definitions and generated TS/Rust snapshots. Completed
   2026-05-12.
2. Add an append-only daemon event store with cursor and idempotency tests.
   Completed 2026-05-12.
3. Bridge one `RuntimeAgentService` session into thread/turn/event records.
   Completed 2026-05-12 for the daemon `RuntimeApiBridge` boundary and injected
   runtime-service projection; the real Rust/Tauri service adapter remains the
   next implementation slice.
4. Expose `/v1/threads/{id}/events` and SSE replay with `Last-Event-ID`.
   Completed 2026-05-12 for the daemon event-store projection.
5. Add SDK `Thread`/`Turn` wrappers over the same stream. Completed
   2026-05-12 for create/open/list/resume/fork, turn submission/list/get, and
   typed event replay over canonical `RuntimeEventEnvelope` rows.
6. Add minimal React Flow runtime thread/turn/event projection.
7. Convert `/v1/runs/*` to aliases over turn/event records. Completed
   2026-05-12 for `/events` and `/replay`; trace/inspect aliases remain on the
   existing trace projection until the live runtime bridge lands.

## Acceptance Gate

The first runtime implementation is acceptable when one live runtime-backed
thread can be:

- started through the daemon;
- streamed through SSE;
- interrupted or completed with terminal turn state;
- replayed from `since_seq=0`;
- resumed after daemon restart from `Last-Event-ID`;
- inspected through SDK and React Flow using the same event ids and seq values;
- proven not to use fixture or synthetic run construction in production mode.
