import assert from "node:assert/strict";
import test from "node:test";

import { createThreadMemoryState } from "./thread-memory-state.mjs";

function createHarness(options = {}) {
  const calls = [];
  const agents = new Map([
    ["agent_a", { id: "agent_a", cwd: "/workspace" }],
  ]);
  const state = createThreadMemoryState({
    agentIdForThread: (threadId) => threadId.replace("thread_", "agent_"),
    doctorHash: () => "abcdef1234567890",
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    fixtureProfileForAgent: () => "fixture.test",
    memoryControlKind: (operation) => `memory_${operation}`,
    memoryEventKind: (operation) => `Memory${operation}`,
    memoryListFilters: (options = {}) => ({
      query: options.query ?? null,
      scope: options.scope ?? null,
    }),
    memoryMutationRawInput: (operation) => `/memory ${operation}`,
    memoryMutationRowLabel: (operation) => `Memory ${operation}`,
    memoryMutationSummary: (operation, { record } = {}) => `Memory ${operation} ${record?.id ?? "none"}.`,
    memoryOperatorControlKind: (operation) => `OperatorControl.Memory${operation}`,
    memoryPolicyOverrides: (policy = {}) => ({ ...policy, normalized: true }),
    memoryRowsForStatus: (status = {}) => [
      { row_kind: "memory_record", memory_record_id: status.records?.[0]?.id ?? null },
    ],
    memoryRuntimeEventKind: (operation) => `memory.${operation}`,
    memoryStatusForProjection: (projection = {}) => ({
      status: projection.records?.length ? "ready" : "empty",
      record_count: projection.records?.length ?? 0,
      records: projection.records ?? [],
      policy: { id: `policy_${projection.threadId ?? "runtime"}` },
    }),
    memoryWorkflowNodeId: (operation) => `runtime.memory.${operation}`,
    memoryWriteBlockReason: (policy = {}, options = {}) => (options.blockMemory ? "blocked_by_test" : null),
    normalizeArray: (values) => Array.isArray(values) ? values : values ? [values] : [],
    operatorControlSource: (source) => source ?? "operator",
    optionalString: (value) => (typeof value === "string" && value ? value : undefined),
    policyError: (message, details) => {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    runtimeError: ({ status, code, message, details }) =>
      Object.assign(new Error(message), { status, code, details }),
    safeId: (value) => String(value).replace(/[^a-z0-9]+/gi, "_"),
    threadIdForAgent: (agentId) => agentId.replace("agent_", "thread_"),
    validateMemoryProjection: (projection = {}) => ({
      ok: true,
      record_count: projection.records?.length ?? 0,
    }),
  });
  const store = {
    agents,
    contextPolicyRunner:
      Object.hasOwn(options, "contextPolicyRunner")
        ? options.contextPolicyRunner
        : {
            planThreadMemoryAgentStateUpdate(request = {}) {
              calls.push({ type: "planThreadMemoryAgentStateUpdate", input: request });
              return {
                status: "planned",
                operation_kind: `thread.${request.control_kind}`,
                agent: { ...request.agent, updatedAt: request.created_at },
              };
            },
          },
    defaultCwd: "/default",
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return agents.get(threadId.replace("thread_", "agent_"));
    },
    getAgent(agentId) {
      calls.push({ type: "getAgent", agentId });
      return agents.get(agentId);
    },
    listMemoryForThread(threadId, options) {
      return state.listMemoryForThread(this, threadId, options);
    },
    listMemoryForAgent(agentId, options) {
      return state.listMemoryForAgent(this, agentId, options);
    },
    memoryProjectionForContext(options) {
      return state.memoryProjectionForContext(this, options);
    },
    recordThreadMemoryMutation(threadId, mutation, body, operation) {
      return state.recordThreadMemoryMutation(this, threadId, mutation, body, operation, "memory.mutation.v1");
    },
    appendThreadMemoryControlEvent(input) {
      return state.appendThreadMemoryControlEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const record = {
        ...event,
        id: "event_1",
        created_at: "2026-06-04T00:00:00.000Z",
      };
      calls.push({ type: "appendRuntimeEvent", event: record });
      return record;
    },
    deleteMemoryRecord(memoryId, body = {}) {
      return state.deleteMemoryRecord(this, memoryId, body);
    },
    memoryStatus(options = {}) {
      return state.memoryStatus(this, options);
    },
    rememberForAgent(agent, options = {}) {
      return state.rememberForAgent(this, agent, options);
    },
    threadForAgent(agent) {
      calls.push({ type: "threadForAgent", agentId: agent.id });
      return { latest_turn_id: "turn_latest" };
    },
    updateMemoryRecord(memoryId, body = {}) {
      return state.updateMemoryRecord(this, memoryId, body);
    },
    writeAgent(agent, operationKind) {
      calls.push({ type: "writeAgent", agent, operationKind });
      agents.set(agent.id, agent);
    },
    memory: {
      effectivePolicy({ agent, threadId, workspace, overrides }) {
        calls.push({ type: "effectivePolicy", agentId: agent?.id, threadId, workspace, overrides });
        return { id: `policy_${threadId}`, overrides };
      },
      pathProjection({ agent, threadId, workspace }) {
        calls.push({ type: "pathProjection", agentId: agent?.id, threadId, workspace });
        return { recordsPath: `${workspace}/${threadId}/memory` };
      },
      projection({ agent, threadId, workspace, filters }) {
        calls.push({ type: "projection", agentId: agent?.id, threadId, workspace, filters });
        return {
          agentId: agent?.id ?? null,
          threadId: threadId ?? null,
          workspace,
          records: [{ id: "memory_1" }],
          filters,
        };
      },
      setPolicy(input) {
        calls.push({ type: "setPolicy", input });
        return { policy: { id: `policy_${input.targetId}` } };
      },
      deleteRecord(input) {
        calls.push({ type: "deleteRecord", input });
        return { record: { id: input.id }, receipt: { id: `receipt_${input.id}` } };
      },
      remember(input) {
        calls.push({ type: "remember", input });
        return { record: { id: "memory_new", workflowNodeId: "runtime.memory" }, receipt: { id: "receipt_memory_new" } };
      },
      updateRecord(input) {
        calls.push({ type: "updateRecord", input });
        return { record: { id: input.id, workflowNodeId: "runtime.memory.edit" }, receipt: { id: `receipt_${input.id}` } };
      },
    },
  };
  return { agents, calls, state, store };
}

test("thread memory state projects thread and agent memory", () => {
  const { calls, state, store } = createHarness();

  assert.deepEqual(state.listMemoryForThread(store, "thread_a", { query: "deploy" }), {
    agentId: "agent_a",
    threadId: "thread_a",
    workspace: "/workspace",
    records: [{ id: "memory_1" }],
    filters: { query: "deploy", scope: null },
  });
  assert.deepEqual(state.listMemoryForAgent(store, "agent_a", { scope: "workspace" }).filters, {
    query: null,
    scope: "workspace",
  });
  assert.equal(state.listMemoryForAgent(store, "agent_a", { thread_id: "thread_custom" }).threadId, "thread_custom");
  assert.equal(state.listMemoryForAgent(store, "agent_a", { threadId: "thread_retired" }).threadId, "thread_a");
  assert.deepEqual(calls.filter((call) => call.type === "projection").map((call) => call.threadId), [
    "thread_a",
    "thread_a",
    "thread_custom",
    "thread_a",
  ]);
});

test("thread memory state handles policies, paths, status, and validation", () => {
  const { state, store } = createHarness();

  assert.equal(state.memoryPolicyForThread(store, "thread_a").id, "policy_thread_a");
  assert.equal(state.memoryPolicyForAgent(store, "agent_a", { thread_id: "thread_custom" }).id, "policy_thread_custom");
  assert.equal(state.memoryPolicyForAgent(store, "agent_a", { threadId: "thread_retired" }).id, "policy_thread_a");
  assert.equal(state.memoryPathForAgent(store, "agent_a").recordsPath, "/workspace/thread_a/memory");
  assert.equal(
    state.memoryPathForAgent(store, "agent_a", { thread_id: "thread_custom" }).recordsPath,
    "/workspace/thread_custom/memory",
  );
  assert.equal(
    state.memoryPathForAgent(store, "agent_a", { threadId: "thread_retired" }).recordsPath,
    "/workspace/thread_a/memory",
  );
  assert.deepEqual(state.memoryStatus(store, { thread_id: "thread_a" }), {
    status: "ready",
    record_count: 1,
    records: [{ id: "memory_1" }],
    policy: { id: "policy_thread_a" },
    thread_id: "thread_a",
    threadId: "thread_a",
    agent_id: "agent_a",
    agentId: "agent_a",
    workspace: "/workspace",
  });
  assert.deepEqual(state.validateMemory(store, { projection: { records: [], threadId: "thread_x" } }), {
    ok: true,
    record_count: 0,
    thread_id: "thread_x",
    threadId: "thread_x",
    agent_id: null,
    agentId: null,
    workspace: null,
  });
});

test("thread memory state applies policy mutations through compatibility store methods", () => {
  const { calls, state, store } = createHarness();

  const threadPolicyResult = state.setMemoryPolicyForThread(store, "thread_a", { policy: { readOnly: true } });
  assert.equal(threadPolicyResult.operation, "policy_update");
  assert.equal(threadPolicyResult.policy.id, "policy_thread_a");
  assert.equal(threadPolicyResult.event.event_kind, "memory.policy_update");
  assert.deepEqual(state.setMemoryPolicyForAgent(store, "agent_a", { read_only: true }), {
    policy: { id: "policy_thread_a" },
  });
  const policyCalls = calls.filter((call) => call.type === "setPolicy").map((call) => call.input);
  assert.equal(policyCalls[0].updates.normalized, true);
  assert.equal(policyCalls[0].updates.readOnly, true);
  assert.equal(policyCalls[1].updates.read_only, true);
});

test("thread memory state records write, edit, and delete mutations", () => {
  const { calls, state, store } = createHarness();

  const write = state.rememberForThread(store, "thread_a", { text: "Remember deploy", source: "test" });
  assert.equal(write.record.id, "memory_new");
  assert.equal(write.receipt_refs[0], "receipt_memory_new");
  assert.equal(write.rows[0].label, "Memory write");

  const edit = state.updateMemoryForThread(store, "thread_a", "memory_1", { text: "Edited" });
  assert.equal(edit.operation, "edit");
  assert.equal(calls.find((call) => call.type === "updateRecord").input.source, "memory_edit_api");

  const deleted = state.deleteMemoryForAgentId(store, "agent_a", "memory_1", { source: "test_delete" });
  assert.equal(deleted.record.id, "memory_1");
  assert.equal(calls.find((call) => call.type === "deleteRecord").input.source, "test_delete");
});

test("thread memory state blocks disallowed writes and emits status events", () => {
  const { agents, calls, state, store } = createHarness();

  assert.throws(
    () => state.rememberForAgentId(store, "agent_a", { text: "Nope", blockMemory: true }),
    /Memory write blocked by policy/,
  );

  const status = state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1");
  assert.equal(status.event.event_stream_id, "stream_thread_a");
  assert.equal(status.event.source, "status_test");
  assert.equal(status.event.payload_schema_version, "memory.status.v1");
  assert.equal(status.event.fixture_profile, "fixture.test");
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 1);
  assert.equal(calls.filter((call) => call.type === "writeAgent").at(-1).operationKind, "thread.memory_status");
  assert.equal(agents.get("agent_a").updatedAt, "2026-06-04T00:00:00.000Z");
});

test("thread memory state fails closed without Rust-planned agent projection", () => {
  const { calls, state, store } = createHarness({
    contextPolicyRunner: {
      planThreadMemoryAgentStateUpdate(request = {}) {
        calls.push({ type: "planThreadMemoryAgentStateUpdate", input: request });
        return {
          status: "planned",
          operation_kind: `thread.${request.control_kind}`,
          agent: null,
        };
      },
    },
  });

  assert.throws(
    () => state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1"),
    (error) => error.code === "thread_memory_state_update_planner_invalid",
  );
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 1);
  assert.equal(calls.some((call) => call.type === "writeAgent"), false);
});

test("thread memory state fails closed without Rust-planned operation kind", () => {
  const { agents, calls, state, store } = createHarness({
    contextPolicyRunner: {
      planThreadMemoryAgentStateUpdate(request = {}) {
        calls.push({ type: "planThreadMemoryAgentStateUpdate", input: request });
        return {
          status: "planned",
          agent: { ...request.agent, updatedAt: request.created_at },
        };
      },
    },
  });

  assert.throws(
    () => state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1"),
    (error) => {
      assert.equal(error.code, "thread_memory_state_update_operation_kind_missing");
      assert.equal(error.details.operationKind, "thread.memory_status");
      return true;
    },
  );
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 1);
  assert.equal(calls.some((call) => call.type === "writeAgent"), false);
  assert.equal(agents.get("agent_a").updatedAt, undefined);
});
