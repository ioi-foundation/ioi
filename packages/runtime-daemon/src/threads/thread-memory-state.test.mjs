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
        return { policy: { id: `policy_${input.target_id}` } };
      },
      deleteRecord(input) {
        calls.push({ type: "deleteRecord", input });
        return { record: { id: input.id }, receipt: { id: `receipt_${input.id}` } };
      },
      remember(input) {
        calls.push({ type: "remember", input });
        return {
          record: {
            id: "memory_new",
            workflow_node_id: "runtime.memory.canonical",
            workflowNodeId: "runtime.memory.retired",
          },
          receipt: { id: "receipt_memory_new" },
        };
      },
      updateRecord(input) {
        calls.push({ type: "updateRecord", input });
        return {
          record: {
            id: input.id,
            workflow_node_id: "runtime.memory.edit.canonical",
            workflowNodeId: "runtime.memory.edit.retired",
          },
          receipt: { id: `receipt_${input.id}` },
        };
      },
    },
  };
  return { agents, calls, state, store };
}

function assertNoRetiredDetailAliases(details) {
  for (const key of ["threadId", "controlKind", "operationKind", "expectedOperationKind"]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
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
    agent_id: "agent_a",
    workspace: "/workspace",
  });
  assert.deepEqual(state.memoryStatus(store, { threadId: "thread_retired" }), {
    status: "ready",
    record_count: 1,
    records: [{ id: "memory_1" }],
    policy: { id: "policy_runtime" },
    thread_id: null,
    agent_id: null,
    workspace: "/default",
  });
  assert.deepEqual(state.memoryStatus(store, { agentId: "agent_a" }), {
    status: "ready",
    record_count: 1,
    records: [{ id: "memory_1" }],
    policy: { id: "policy_runtime" },
    thread_id: null,
    agent_id: null,
    workspace: "/default",
  });
  assert.deepEqual(state.validateMemory(store, { projection: { records: [], threadId: "thread_x" } }), {
    ok: true,
    record_count: 0,
    thread_id: "thread_x",
    agent_id: null,
    workspace: null,
  });
});

test("thread memory state applies policy mutations through canonical store methods", () => {
  const { calls, state, store } = createHarness();

  const threadPolicyResult = state.setMemoryPolicyForThread(store, "thread_a", { policy: { read_only: true } });
  assert.equal(threadPolicyResult.operation, "policy_update");
  assert.equal(threadPolicyResult.policy.id, "policy_thread_a");
  assert.equal(threadPolicyResult.event.event_kind, "memory.policy_update");
  assert.deepEqual(state.setMemoryPolicyForAgent(store, "agent_a", { read_only: true }), {
    policy: { id: "policy_thread_a" },
  });
  const policyCalls = calls.filter((call) => call.type === "setPolicy").map((call) => call.input);
  assert.equal(policyCalls[0].updates.normalized, true);
  assert.equal(policyCalls[0].updates.read_only, true);
  assert.equal(policyCalls[1].updates.read_only, true);
});

test("agent memory mutation bodies ignore retired camelCase identity aliases", () => {
  const { calls, state, store } = createHarness();

  state.rememberForAgentId(store, "agent_a", {
    text: "Canonical thread",
    thread_id: "thread_canonical",
  });
  state.rememberForAgentId(store, "agent_a", {
    text: "Retired thread",
    threadId: "thread_retired",
  });
  state.updateMemoryForAgentId(store, "agent_a", "memory_edit", {
    text: "Edit canonical",
    thread_id: "thread_canonical_edit",
  });
  state.updateMemoryForAgentId(store, "agent_a", "memory_edit_retired", {
    text: "Edit retired",
    threadId: "thread_retired_edit",
  });
  state.deleteMemoryForAgentId(store, "agent_a", "memory_delete", {
    thread_id: "thread_canonical_delete",
  });
  state.deleteMemoryForAgentId(store, "agent_a", "memory_delete_retired", {
    threadId: "thread_retired_delete",
  });
  state.setMemoryPolicyForAgent(store, "agent_a", {
    thread_id: "thread_canonical_policy",
    target_type: "workflow",
    target_id: "workflow-policy",
  });
  state.setMemoryPolicyForAgent(store, "agent_a", {
    threadId: "thread_retired_policy",
    targetType: "workflow",
    targetId: "retired-policy",
  });

  assert.deepEqual(calls.filter((call) => call.type === "effectivePolicy").map((call) => call.threadId), [
    "thread_canonical",
    "thread_a",
    "thread_canonical_edit",
    "thread_a",
    "thread_canonical_delete",
    "thread_a",
  ]);
  assert.deepEqual(calls.filter((call) => call.type === "remember").map((call) => call.input.threadId), [
    "thread_canonical",
    "thread_a",
  ]);
  const policyCalls = calls.filter((call) => call.type === "setPolicy").map((call) => call.input);
  assert.equal(policyCalls.at(-2).thread_id, "thread_canonical_policy");
  assert.equal(policyCalls.at(-2).target_type, "workflow");
  assert.equal(policyCalls.at(-2).target_id, "workflow-policy");
  assert.equal(Object.hasOwn(policyCalls.at(-2), "threadId"), false);
  assert.equal(Object.hasOwn(policyCalls.at(-2), "targetType"), false);
  assert.equal(Object.hasOwn(policyCalls.at(-2), "targetId"), false);
  assert.equal(policyCalls.at(-1).thread_id, "thread_a");
  assert.equal(policyCalls.at(-1).target_type, "thread");
  assert.equal(policyCalls.at(-1).target_id, "thread_a");
  assert.equal(Object.hasOwn(policyCalls.at(-1), "threadId"), false);
  assert.equal(Object.hasOwn(policyCalls.at(-1), "targetType"), false);
  assert.equal(Object.hasOwn(policyCalls.at(-1), "targetId"), false);
});

test("thread memory state records write, edit, and delete mutations", () => {
  const { calls, state, store } = createHarness();

  const write = state.rememberForThread(store, "thread_a", { text: "Remember deploy", source: "test" });
  assert.equal(write.record.id, "memory_new");
  assert.equal(write.receipt_refs[0], "receipt_memory_new");
  assert.equal(write.rows[0].label, "Memory write");
  assert.equal(write.rows[0].workflow_node_id, "runtime.memory.canonical");
  for (const field of [
    "schemaVersion",
    "memoryOperation",
    "mutationStatus",
    "threadId",
    "agentId",
    "memoryRecordId",
    "memoryPolicyId",
    "receiptRefs",
    "memoryRows",
  ]) {
    assert.equal(Object.hasOwn(write, field), false);
  }

  const edit = state.updateMemoryForThread(store, "thread_a", "memory_1", { text: "Edited" });
  assert.equal(edit.operation, "edit");
  assert.equal(edit.rows[0].workflow_node_id, "runtime.memory.edit.canonical");
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

test("thread memory state ignores retired request identity aliases", () => {
  const { calls, state, store } = createHarness();

  const retired = state.recordThreadMemoryStatus(
    store,
    "thread_a",
    {
      source: "status_alias_test",
      turnId: "turn_retired",
      workflowGraphId: "graph_retired",
      workflowNodeId: "node_retired",
      idempotencyKey: "memory_idempotency_retired",
    },
    "memory.status.v1",
  );

  assert.equal(retired.event.turn_id, "turn_latest");
  assert.equal(retired.event.workflow_graph_id, null);
  assert.equal(retired.event.workflow_node_id, "runtime.memory-manager");
  assert.match(retired.event.idempotency_key, /^thread:thread_a:memory:memory_status:/);

  const canonical = state.recordThreadMemoryStatus(
    store,
    "thread_a",
    {
      source: "status_canonical_test",
      turn_id: "turn_canonical",
      workflow_graph_id: "graph_canonical",
      workflow_node_id: "node_canonical",
      idempotency_key: "memory_idempotency_canonical",
    },
    "memory.status.v1",
  );

  assert.equal(canonical.event.turn_id, "turn_canonical");
  assert.equal(canonical.event.workflow_graph_id, "graph_canonical");
  assert.equal(canonical.event.workflow_node_id, "node_canonical");
  assert.equal(canonical.event.idempotency_key, "memory_idempotency_canonical");
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 2);
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
    (error) => {
      assert.equal(error.code, "thread_memory_state_update_planner_invalid");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.control_kind, "memory_status");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
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
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.control_kind, "memory_status");
      assert.equal(error.details.operation_kind, "thread.memory_status");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 1);
  assert.equal(calls.some((call) => call.type === "writeAgent"), false);
  assert.equal(agents.get("agent_a").updatedAt, undefined);
});

test("thread memory state rejects unexpected Rust-planned operation kind with canonical details", () => {
  const { agents, calls, state, store } = createHarness({
    contextPolicyRunner: {
      planThreadMemoryAgentStateUpdate(request = {}) {
        calls.push({ type: "planThreadMemoryAgentStateUpdate", input: request });
        return {
          status: "planned",
          operation_kind: "thread.memory_policy",
          agent: { ...request.agent, updatedAt: request.created_at },
        };
      },
    },
  });

  assert.throws(
    () => state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1"),
    (error) => {
      assert.equal(error.code, "thread_memory_state_update_operation_kind_mismatch");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.control_kind, "memory_status");
      assert.equal(error.details.expected_operation_kind, "thread.memory_status");
      assert.equal(error.details.operation_kind, "thread.memory_policy");
      assertNoRetiredDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(calls.filter((call) => call.type === "planThreadMemoryAgentStateUpdate").length, 1);
  assert.equal(calls.some((call) => call.type === "writeAgent"), false);
  assert.equal(agents.get("agent_a").updatedAt, undefined);
});
