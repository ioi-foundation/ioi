import assert from "node:assert/strict";
import test from "node:test";

import { createThreadTurnProjection } from "./thread-turn-projection.mjs";

function createProjection() {
  return createThreadTurnProjection({
    eventStreamIdForThread: (threadId) => `stream:${threadId}`,
    fixtureProfileForAgent: (agent) => agent.runtime_profile ?? "fixture",
    lifecycleStatusForRun: (status) => status === "completed" ? "completed" : "running",
    normalizedAgentRuntimeControls: (agent) => agent.runtimeControls ?? { mode: "agent", approval_mode: "suggest", model: {} },
    runtimeSessionIdForAgent: (agent) => `session:${agent.id}`,
    runtimeThreadSchemaVersion: "thread.schema",
    runtimeTurnIdForRun: (run) => run.runtimeTurnId ?? `turn_${run.id.replace(/^run_/, "")}`,
    runtimeTurnSchemaVersion: "turn.schema",
    runtimeUsageTelemetryForRun: ({ run, threadId }) => ({ scope: "run", runId: run.id, threadId }),
    runtimeUsageTelemetryForThread: ({ threadId, runs, subagents }) => ({
      scope: "thread",
      threadId,
      runIds: runs.map((run) => run.id),
      subagentIds: subagents.map((subagent) => subagent.id),
    }),
    runtimeError(input) {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
    threadIdForAgent: (agentId) => `thread_${agentId.replace(/^agent_/, "")}`,
    threadModeForRunMode: (mode, fallback) => mode === "dry_run" ? "custom" : fallback ?? "agent",
    threadStatusForAgent: (status) => status === "archived" ? "archived" : "active",
    turnIdForRun: (runId) => `turn_${runId.replace(/^run_/, "")}`,
  });
}

function createStore({ agent, runs = [], events = [] }) {
  return {
    agents: new Map([[agent.id, agent]]),
    runs,
    projectionRequests: [],
    subagents: new Map([
      ["sub_one", { id: "sub_one", parent_thread_id: `thread_${agent.id.replace(/^agent_/, "")}` }],
      ["sub_retired", { id: "sub_retired", parentThreadId: `thread_${agent.id.replace(/^agent_/, "")}` }],
      ["sub_other", { id: "sub_other", parent_thread_id: "thread_other" }],
    ]),
    memory: {
      list: () => [{ id: "memory_one" }, { id: "memory_two" }],
    },
    getAgent(agentId) {
      return this.agents.get(agentId);
    },
    latestRuntimeEventSeq() {
      return events.at(-1)?.seq ?? 0;
    },
    listRuns(agentId) {
      return runs.filter((run) => run.agentId === agentId);
    },
    projectRunEvents() {
      this.projectRunEventsCalled = true;
    },
    projectThreadEvents() {
      this.projectThreadEventsCalled = true;
    },
    projectRuntimeThreadTurnProjectionForThread(inputStore, request) {
      this.projectionRequests.push(request);
      return {
        projected: true,
        record: request.projection_kind === "thread"
          ? threadProjectionRecordForTest(request)
          : turnProjectionRecordForTest(request),
      };
    },
    runtimeEventsForTurn() {
      return events;
    },
  };
}

function turnIdForRunId(runId) {
  return String(runId).replace(/^run_/, "turn_");
}

function threadProjectionRecordForTest(request) {
  const latestRun = request.runs.at(-1) ?? {};
  const usage = request.usage_telemetry;
  return {
    schema_version: request.thread_schema_version,
    thread_id: request.thread_id,
    session_id: request.session_id,
    agent_id: request.agent.agent_id,
    workspace_root: request.agent.workspace_root,
    title: latestRun.objective ?? request.agent.workspace_root,
    mode: request.runtime_controls.mode,
    approval_mode: request.runtime_controls.approval_mode,
    trust_profile: "local_private",
    model_route: request.agent.model_id,
    status: latestRun.turn_status === "interrupted" ? "interrupted" : request.agent.status,
    latest_turn_id: latestRun.run_id ? latestRun.turn_id ?? turnIdForRunId(latestRun.run_id) : null,
    latest_seq: request.latest_seq,
    event_stream_id: request.event_stream_id,
    workflow_graph_id: null,
    harness_binding_id: null,
    agentgres_projection_ref: `agents/${request.agent.agent_id}.json`,
    created_at: request.agent.created_at,
    updated_at: latestRun.updated_at ?? request.agent.updated_at,
    archived_at: request.agent.status === "archived" ? request.agent.updated_at : null,
    fixture_profile: request.fixture_profile,
    created_at_ms: request.created_at_ms,
    updated_at_ms: request.updated_at_ms,
    workspace: request.agent.workspace_root,
    requested_model: request.agent.requested_model_id ?? request.agent.model_id,
    model_route_id: request.agent.model_route_id ?? null,
    model_route_receipt_id: request.agent.model_route_receipt_id ?? null,
    model_route_decision: request.agent.model_route_decision ?? null,
    selected_model: request.agent.model_id,
    reasoning_effort: request.agent.model_route_decision?.reasoning_effort ?? null,
    runtime_controls: request.runtime_controls,
    memory_count: request.memory_count,
    archived: request.agent.status === "archived",
    evidence_refs: ["agentgres_canonical_state_projection", "rust_runtime_thread_turn_projection"],
    runtime_profile: request.runtime_profile,
    runtime_bridge_id: request.runtime_bridge_id,
    runtime_bridge_source: request.runtime_bridge_source,
    usage,
    usage_telemetry: usage,
  };
}

function turnProjectionRecordForTest(request) {
  const run = request.run;
  const isOpen = ["queued", "running", "waiting_for_approval", "waiting_for_input"].includes(request.status);
  const inputItemIds = request.events
    .filter((event) => event.event_kind === "turn.started")
    .map((event) => event.item_id);
  const outputItemIds = request.events
    .filter((event) => event.event_kind !== "turn.started")
    .map((event) => event.item_id);
  const usage = request.usage_telemetry;
  return {
    schema_version: request.turn_schema_version,
    turn_id: request.turn_id,
    thread_id: request.thread_id,
    parent_turn_id: null,
    request_id: run.run_id,
    status: request.status,
    input_item_ids: inputItemIds,
    output_item_ids: outputItemIds,
    events: request.events,
    seq_start: request.events.at(0)?.seq ?? null,
    seq_end: isOpen ? null : request.events.at(-1)?.seq ?? null,
    started_at: run.created_at,
    completed_at: isOpen ? null : request.completed_at,
    mode: request.mode,
    approval_mode: request.approval_mode,
    model_route_decision_id: run.model_route_decision_id ?? null,
    usage,
    usage_telemetry: usage,
    result: run.result ?? "",
    output: run.result ?? "",
    text: run.result ?? "",
    stop_reason: run.trace?.stop_condition?.reason ?? null,
    error: run.status === "failed" ? run.result : null,
    conversation: run.conversation ?? [],
    rollback_snapshot_id: null,
    quality_ledger_ref: run.trace?.quality_ledger?.ledgerId ?? run.trace?.quality_ledger?.ledger_id ?? null,
    workflow_execution_ref: null,
    fixture_profile: request.fixture_profile,
    started_at_ms: request.created_at_ms,
    completed_at_ms: isOpen ? null : request.updated_at_ms,
    error_summary: run.status === "failed" ? run.result : null,
    model_route_decision: run.model_route_decision ?? null,
    model_route_receipt_id: run.model_route_receipt_id ?? null,
    active_skill_hook_manifest_ref: run.active_skill_hook_manifest_ref ?? null,
    active_skill_set_hash: run.active_skill_set_hash ?? null,
    active_hook_set_hash: run.active_hook_set_hash ?? null,
    memory_refs: run.memory_refs ?? [],
    memory_write_receipt_ids: run.memory_write_receipt_ids ?? [],
    evidence_refs: [
      "agentgres_canonical_state_projection",
      `run:${run.run_id}`,
      run.active_skill_hook_manifest_ref,
    ].filter(Boolean),
  };
}

const retiredUsageProjectionAliasKeys = [
  "usageTelemetry",
  "runtime_usage",
  "runtimeUsage",
];

function assertMissingKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(record, key), false, `retired alias key ${key} must be absent`);
  }
}

test("thread projection includes latest run, usage, memory, and interrupted status", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    status: "active",
    modelId: "qwen",
    requestedModelId: "auto",
    modelRouteId: "route.local-first",
    modelRouteReceiptId: "receipt-route",
    modelRouteDecision: { reasoning_effort: "medium" },
    runtime_profile: "runtime_service",
    runtime_bridge_id: "bridge_runtime",
    runtime_bridge_source: "rust_core",
    runtimeControls: { mode: "agent", approval_mode: "suggest", model: { reasoning_effort: "low" } },
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:01.000Z",
  };
  const store = createStore({
    agent,
    runs: [
      { id: "run_one", agentId: "agent_one", objective: "Older", createdAt: "2026-06-03T00:00:02.000Z", updatedAt: "2026-06-03T00:00:02.000Z" },
      { id: "run_two", agentId: "agent_one", objective: "Latest", turnStatus: "interrupted", createdAt: "2026-06-03T00:00:03.000Z", updatedAt: "2026-06-03T00:00:04.000Z" },
    ],
    events: [{ seq: 7 }],
  });

  const thread = createProjection().threadForAgent(store, agent);

  assert.equal(thread.schema_version, "thread.schema");
  assert.equal(thread.thread_id, "thread_one");
  assert.equal(thread.title, "Latest");
  assert.equal(thread.status, "interrupted");
  assert.equal(thread.latest_turn_id, "turn_two");
  assert.equal(thread.latest_seq, 7);
  assert.equal(thread.memory_count, 2);
  assert.equal(thread.reasoning_effort, "medium");
  assert.equal(thread.runtime_profile, "runtime_service");
  assert.equal(thread.runtime_bridge_id, "bridge_runtime");
  assert.equal(thread.runtime_bridge_source, "rust_core");
  assert.deepEqual(thread.usage.subagentIds, ["sub_one"]);
  assert.equal(thread.usage_telemetry, thread.usage);
  assertMissingKeys(thread, retiredUsageProjectionAliasKeys);
  assert.equal(store.projectThreadEventsCalled, true);
});

test("thread projection ignores retired runtime identity aliases", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    status: "active",
    modelId: "qwen",
    runtimeProfile: "runtime_alias",
    runtimeBridgeId: "bridge_alias",
    runtimeBridgeSource: "source_alias",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:01.000Z",
  };
  const store = createStore({ agent });

  const thread = createProjection().threadForAgent(store, agent);

  assert.equal(thread.runtime_profile, "fixture");
  assert.equal(thread.runtime_bridge_id, null);
  assert.equal(thread.runtime_bridge_source, null);
});

test("turn projection distinguishes closed and open turns", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    runtimeControls: { mode: "agent", approval_mode: "review" },
  };
  const events = [
    { seq: 1, event_kind: "turn.started", item_id: "item-in" },
    { seq: 2, event_kind: "response.completed", item_id: "item-out" },
  ];
  const store = createStore({ agent, events });
  const projection = createProjection();
  const completed = projection.turnForRun(store, {
    id: "run_one",
    agentId: "agent_one",
    status: "completed",
    result: "Done",
    mode: "send",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:05.000Z",
    trace: { stopCondition: { reason: "final" }, qualityLedger: { ledgerId: "ledger-one" } },
    memoryRecords: [{ id: "memory-one" }],
    memoryWriteReceipts: [{ id: "receipt-memory" }],
    activeSkillHookManifest: { manifestId: "manifest-one", activeSkillSetHash: "skill-hash", activeHookSetHash: "hook-hash" },
  });

  assert.equal(completed.schema_version, "turn.schema");
  assert.equal(completed.turn_id, "turn_one");
  assert.equal(completed.seq_start, 1);
  assert.equal(completed.seq_end, 2);
  assert.equal(completed.completed_at, "2026-06-03T00:00:05.000Z");
  assert.deepEqual(completed.input_item_ids, ["item-in"]);
  assert.deepEqual(completed.output_item_ids, ["item-out"]);
  assert.equal(completed.stop_reason, "final");
  assert.deepEqual(completed.memory_refs, ["memory-one"]);
  assert.equal(completed.active_skill_hook_manifest_ref, "manifest-one");
  assert.equal(completed.usage_telemetry, completed.usage);
  assertMissingKeys(completed, retiredUsageProjectionAliasKeys);

  const open = projection.turnForRun(store, {
    id: "run_open",
    agentId: "agent_one",
    status: "running",
    mode: "dry_run",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:05.000Z",
  });

  assert.equal(open.status, "running");
  assert.equal(open.seq_end, null);
  assert.equal(open.completed_at, null);
  assert.equal(open.mode, "custom");
  assertMissingKeys(open, retiredUsageProjectionAliasKeys);
  assert.equal(store.projectRunEventsCalled, true);
});

test("turn projection ignores retired persisted approval mode aliases", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    runtimeControls: {
      mode: "review",
      approvalMode: "never_prompt",
      approval_mode: "human_required",
    },
  };
  const store = createStore({ agent });
  const turn = createProjection().turnForRun(store, {
    id: "run_approval_alias",
    agentId: "agent_one",
    status: "running",
    mode: "send",
    approvalMode: "retired_run_approval_mode",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:05.000Z",
  });

  assert.equal(turn.mode, "review");
  assert.equal(turn.approval_mode, "human_required");
  assert.notEqual(turn.approval_mode, "retired_run_approval_mode");
});

test("turn projection ignores retired run usage aliases", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    runtimeControls: { mode: "agent", approval_mode: "review" },
  };
  const store = createStore({ agent });
  const turn = createProjection().turnForRun(store, {
    id: "run_legacy_usage",
    agentId: "agent_one",
    status: "completed",
    mode: "send",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:05.000Z",
    usageTelemetry: { total_tokens: 100 },
    runtimeUsage: { total_tokens: 200 },
  });

  assert.deepEqual(turn.usage_telemetry, {
    scope: "run",
    runId: "run_legacy_usage",
    threadId: "thread_one",
  });
  assert.equal(turn.usage_telemetry, turn.usage);
  assert.notEqual(turn.usage_telemetry.total_tokens, 100);
  assert.notEqual(turn.usage_telemetry.total_tokens, 200);
  assertMissingKeys(turn, retiredUsageProjectionAliasKeys);
});

test("thread and turn projection fail closed without Rust projection API", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    status: "active",
    createdAt: "2026-06-03T00:00:00.000Z",
    updatedAt: "2026-06-03T00:00:01.000Z",
  };
  const store = createStore({
    agent,
    runs: [{ id: "run_one", agentId: "agent_one", status: "running", createdAt: "2026-06-03T00:00:00.000Z", updatedAt: "2026-06-03T00:00:01.000Z" }],
  });
  delete store.projectRuntimeThreadTurnProjectionForThread;
  const projection = createProjection();

  assert.throws(
    () => projection.threadForAgent(store, agent),
    (error) => {
      assert.equal(error.code, "runtime_thread_turn_projection_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.thread_turn_projection");
      assert.equal(error.details.projection_kind, "thread");
      return true;
    },
  );
  assert.throws(
    () => projection.turnForRun(store, store.runs[0]),
    (error) => {
      assert.equal(error.code, "runtime_thread_turn_projection_rust_core_required");
      assert.equal(error.details.projection_kind, "turn");
      assert.equal(error.details.turn_id, "turn_one");
      return true;
    },
  );
});
