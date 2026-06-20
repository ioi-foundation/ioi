# Hypervisor Unified Rust Daemon — Lifecycle + MCP Migration Plan

Status: implementation-grade plan (active)
Branch: `hypervisor-real-execution-master-guide`
Last reviewed: 2026-06-20
Supersedes: the "bridge the 16 daemon-core APIs" approach (a napi/sync-CLI/async-cascade bridge was rejected).

## Direction (user-set)

The Rust `crates/node/src/bin/hypervisor-daemon.rs` **is** the daemon; JS/TS becomes a
client only. Do NOT build a napi bridge, a sync-CLI invoker, or async-cascade the JS
daemon-core APIs. Move whole route FAMILIES into Rust so the kernel planner calls become
internal Rust function calls — that deletes the sync/async mismatch because the synchronous
JS caller disappears. JS keeps only: product UI, SDK ergonomics, tests/fixtures, thin
client libs.

**Done-rule (per family):** a family is Rust-owned only when public truth returns from the
Rust HTTP/IPC daemon over Rust admission/replay AND the JS owner is deleted or demoted to a
pure-forwarding client; conformance must REJECT restored JS route logic.

## First slice = combined thread/agent/run/turn LIFECYCLE + MCP

Chosen because the families are co-entangled (map-proven):
- thread-create calls `planMcpManagerCatalogProjection` INTERNALLY (via `mcpRegistryForWorkspace`)
  — that internal call is the live-gate 502, NOT an HTTP route. Only moving lifecycle into Rust
  (so thread-create runs in Rust, calling the planner as an internal fn) removes it.
- MCP control planners mutate `state_dir/agents/*.json` and read the runtime-event seq — they
  cannot own truth until agent/thread state is Rust-owned.

## Key architecture facts (from the three maps)

- **Kernel services are unit structs** with `Default`/`new()`: `RuntimeKernelService`
  (`crates/services/src/agentic/runtime/kernel/mod.rs:387`) and `ModelMountCore`. The daemon
  calls planners statelessly: `RuntimeKernelService.plan_*(&req)` with `state_dir` in the
  request. Same idiom the model-mount routes already use.
- **The kernel planners VALIDATE/STAMP candidates the JS builds — they do not build run/thread
  content.** The deterministic run content (events[], conversation[], trace, receipts) is built
  by JS `buildRun` (`index.mjs:~3319`) and the agent/thread candidates by
  `buildAgentCreateCandidate` / `buildThreadCreateCandidate` / `initialThreadRuntimeControls`
  (`runtime-agent-run-lifecycle.mjs`). **These candidate builders must be ported to Rust.**
- **Byte-compatible state is mandatory** (`crates/services/.../kernel/agentgres_admission.rs`):
  files = `serde_json::to_string_pretty(payload) + "\n"`; filename = `safe_agentgres_component`
  (keep `[A-Za-z0-9_.-]`, else `_`, empty→`runtime`); events =
  `events/<sha256_hex(event_stream_id)>.jsonl` (JSONL). `content_hash` =
  `sha256` over canonical sorted-key JSON. Every agent/subagent/artifact/receipt/memory commit
  requires non-empty `receipt_refs`. Run commit fans out the full bundle
  (runs/agents/tasks/jobs/checklists/receipts/artifacts/policy-decisions/authority-decisions/
  stop-conditions/scorecards/ledgers/quality/projections). state_dir subdirs:
  `thread-persistence.mjs:13-41`. The daemon's `data_dir` becomes this unified state_dir.
- **Routes are registered inline** in the daemon `main()` Router chain (hypervisor-daemon.rs
  :129-247). Add new handlers in a SUBDIRECTORY submodule to dodge cargo autobin:
  `#[path = "hypervisor_daemon_routes/lifecycle_routes.rs"] mod lifecycle_routes;` then
  `.route(..., post(lifecycle_routes::handle_*))`. Make shared helpers (`DaemonState`,
  `AppError`, `authorize`, `persist_record`, `iso_now`, `short_hash`, `read_record_dir`,
  `read_projection_record`, model-mount imports) `pub(crate)`/`pub(super)`.

## Ratchet gate (the verification engine — mirrors the proven 5c e2e ratchet)

New `scripts/validate-runtime-lifecycle-e2e.mjs`: spawn the Rust daemon via
`scripts/lib/rust-hypervisor-daemon.mjs` (already built for route-control), mint a token, then
exercise the thread→turn→event→run→control→subagent→task/job→MCP flow over HTTP, asserting the
same contract as `scripts/lib/live-runtime-daemon-contract.test.mjs` (the keystone test is
"local daemon projects Agentgres runs through thread, turn, and monotonic event records",
contract line 1520). Each route family built advances the ratchet one step. Drive it green
step-by-step; commit at green checkpoints.

## Per-route ratchet sequence

1. **POST /v1/threads + GET /v1/threads/:id** — build agent+thread candidates (route via the
   existing Rust route-control; MCP registry via `plan_mcp_manager_catalog_projection`;
   runtime controls), `plan_thread_create_state_update`, `commit_runtime_agent_state` (with a
   thread.create receipt for receipt_refs), admit `thread.started` event
   (`admit_runtime_thread_event`), project the thread record
   (`project_runtime_thread_turn_projection`). Assert thread record
   (schema `ioi.runtime.thread.v1`, ids, event_stream_id, latest_seq 1, model_route_decision).
2. **POST /v1/threads/:id/turns + GET .../turns[/:id]** — port `buildRun` (deterministic run
   candidate: events/conversation/trace/receipts), `plan_run_create_state_update`,
   `commit_runtime_run_state_to_dir` (full bundle), project the turn record
   (`ioi.runtime.turn.v1`, status completed, stop_reason evidence_sufficient).
3. **GET /v1/threads/:id/events[/stream] + /v1/runs/:id/events|replay (SSE)** — project events
   (`project_runtime_thread_events`); SSE one-shot frames; honor `since_seq`, `Last-Event-ID`,
   future-cursor → 409 `event_cursor_out_of_range`.
4. **Runs**: GET /v1/runs[/:id...], POST /v1/runs/:id/cancel (`plan_run_cancel_state_update`).
5. **Thread control**: POST /v1/threads/:id/{mode,model,thinking}
   (`plan_thread_control_agent_state_update` + workspace-trust for mode).
6. **Agents collection/item**: POST/GET /v1/agents, lifecycle status transitions.
7. **Subagents**: spawn/wait/input/resume/assign/cancel (+ propagate).
8. **Tasks/Jobs**: create/list/get/cancel (materialized off runs).
9. **MCP family** (`/v1/threads/:id/mcp/*`): catalog/tool-search/tool-fetch projections,
   control mutations (`plan_mcp_control_agent_state_update`), serve JSON-RPC. (Map: task
   wik2n35uh.)
10. The long tail of contract surfaces (doctor, repository-context, skills/hooks, approvals,
    workspace-trust, authority-evidence, computer-use, memory) as later ratchet steps.

## Gate-repoint surface (in-process `daemon.store.*` the live gate uses, must become routes)

`live-runtime-daemon-contract.test.mjs` reaches into the JS store directly in places that have
no HTTP equivalent; against the Rust daemon each needs a real (or test-only seed) route:
- `appendRuntimeEvent` / `runtimeEventsForStream` (lines 629, 4127-4186, 10124, 10258, 10455,
  10883) — raw event append (idempotent) + stream read; items 1,12-15 are all "seed a synthetic
  source event" → one event-injection endpoint covers them.
- `modelMounting.upsertRoute` (line 4217) — model-route seed (fallback-decision test).
- `subagents.get` / `writeSubagent` (lines 5274, 5279) — force a subagent "running" (concurrency
  test).
Plan: new ratchet gate avoids these initially; when repointing the keystone gate later, add a
small test-only admin/seed surface OR produce the effects through the normal run flow.

## Family arc after lifecycle+MCP

memory → approvals/governed-admission → workspace/diagnostics → coding tools →
conversation artifacts → remaining protocol clients. Then retire the JS owners + conformance
guard.
