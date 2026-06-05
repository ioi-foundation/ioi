import assert from "node:assert/strict";
import test from "node:test";

import { createThreadTurnProjection } from "./thread-turn-projection.mjs";

function createProjection() {
  return createThreadTurnProjection({
    eventStreamIdForThread: (threadId) => `stream:${threadId}`,
    fixtureProfileForAgent: (agent) => agent.runtimeProfile ?? "fixture",
    lifecycleStatusForRun: (status) => status === "completed" ? "completed" : "running",
    normalizedAgentRuntimeControls: (agent) => agent.runtimeControls ?? { mode: "agent", approvalMode: "suggest", model: {} },
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
    threadIdForAgent: (agentId) => `thread_${agentId.replace(/^agent_/, "")}`,
    threadModeForRunMode: (mode, fallback) => mode === "dry_run" ? "custom" : fallback ?? "agent",
    threadStatusForAgent: (status) => status === "archived" ? "archived" : "active",
    turnIdForRun: (runId) => `turn_${runId.replace(/^run_/, "")}`,
  });
}

function createStore({ agent, runs = [], events = [] }) {
  return {
    agents: new Map([[agent.id, agent]]),
    subagents: new Map([
      ["sub_one", { id: "sub_one", parent_thread_id: `thread_${agent.id.replace(/^agent_/, "")}` }],
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
    runtimeEventsForTurn() {
      return events;
    },
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
    modelRouteDecision: { reasoningEffort: "medium" },
    runtimeControls: { mode: "agent", approvalMode: "suggest", model: { reasoningEffort: "low" } },
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
  assert.deepEqual(thread.usage.subagentIds, ["sub_one"]);
  assert.equal(thread.usage_telemetry, thread.usage);
  assertMissingKeys(thread, retiredUsageProjectionAliasKeys);
  assert.equal(store.projectThreadEventsCalled, true);
});

test("turn projection distinguishes closed and open turns", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    runtimeControls: { mode: "agent", approvalMode: "review" },
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

test("turn projection ignores retired run usage aliases", () => {
  const agent = {
    id: "agent_one",
    cwd: "/workspace",
    runtimeControls: { mode: "agent", approvalMode: "review" },
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
