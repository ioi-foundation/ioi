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
      policy: { id: `policy_${projection.thread_id ?? "runtime"}` },
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
        return { records_path: `${workspace}/${threadId}/memory` };
      },
      projection({ agent, threadId, workspace, filters }) {
        calls.push({ type: "projection", agentId: agent?.id, threadId, workspace, filters });
        return {
          agent_id: agent?.id ?? null,
          thread_id: threadId ?? null,
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
          },
          receipt: { id: `receipt_${input.id}` },
        };
      },
    },
  };
  return { agents, calls, state, store };
}

function assertNoRetiredDetailAliases(details) {
  for (const key of ["rustCoreBoundary", "operationKind", "threadId", "agentId", "memoryId", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertThreadMemoryRustCoreRequired(error, expected = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_thread_memory_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.thread_memory_control");
  assert.equal(error.details.operation, "thread_memory_control");
  assert.equal(error.details.operation_kind, "thread_memory_control");
  assert.equal(error.details.requested_operation, expected.operation ?? null);
  assert.equal(error.details.requested_control_kind, expected.controlKind ?? null);
  assert.equal(error.details.thread_id, expected.threadId ?? null);
  assert.equal(error.details.agent_id, expected.agentId ?? null);
  assert.equal(error.details.memory_id, expected.memoryId ?? null);
  assert.deepEqual(error.details.evidence_refs, [
    "runtime_thread_memory_control_js_facade_retired",
    "runtime_thread_memory_read_projection_js_facade_retired",
    "runtime_thread_memory_write_js_facade_retired",
    "runtime_thread_memory_policy_js_facade_retired",
    "runtime_thread_memory_status_validation_js_facade_retired",
    "runtime_memory_state_store_js_mutation_retired",
    "rust_daemon_core_thread_memory_control_required",
    "agentgres_thread_memory_state_truth_required",
  ]);
  assertNoRetiredDetailAliases(error.details);
}

test("thread memory state projects thread and agent memory", () => {
  const { calls, state, store } = createHarness();

  assert.deepEqual(state.listMemoryForThread(store, "thread_a", { query: "deploy" }), {
    agent_id: "agent_a",
    thread_id: "thread_a",
    workspace: "/workspace",
    records: [{ id: "memory_1" }],
    filters: { query: "deploy", scope: null },
  });
  assert.deepEqual(state.listMemoryForAgent(store, "agent_a", { scope: "workspace" }).filters, {
    query: null,
    scope: "workspace",
  });
  assert.equal(state.listMemoryForAgent(store, "agent_a", { thread_id: "thread_custom" }).thread_id, "thread_custom");
  assert.equal(state.listMemoryForAgent(store, "agent_a", { threadId: "thread_retired" }).thread_id, "thread_a");
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
  assert.equal(state.memoryPathForAgent(store, "agent_a").records_path, "/workspace/thread_a/memory");
  assert.equal(
    state.memoryPathForAgent(store, "agent_a", { thread_id: "thread_custom" }).records_path,
    "/workspace/thread_custom/memory",
  );
  assert.equal(
    state.memoryPathForAgent(store, "agent_a", { threadId: "thread_retired" }).records_path,
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
  assert.deepEqual(state.validateMemory(store, { projection: { records: [], threadId: "thread_retired" } }), {
    ok: true,
    record_count: 0,
    thread_id: null,
    agent_id: null,
    workspace: null,
  });
  assert.deepEqual(
    state.validateMemory(store, {
      projection: {
        records: [],
        threadId: "thread_retired",
        agentId: "agent_retired",
        thread_id: "thread_x",
        agent_id: "agent_x",
      },
    }),
    {
      ok: true,
      record_count: 0,
      thread_id: "thread_x",
      agent_id: "agent_x",
      workspace: null,
    },
  );
});

test("thread memory mutation and policy facades fail closed before JS store mutation", () => {
  const { calls, state, store } = createHarness();

  const cases = [
    {
      call: () => state.rememberForThread(store, "thread_a", { text: "Remember deploy" }),
      expected: { operation: "write", controlKind: "memory_write", threadId: "thread_a" },
    },
    {
      call: () => state.setMemoryPolicyForThread(store, "thread_a", { policy: { read_only: true } }),
      expected: { operation: "policy_update", controlKind: "memory_policy_update", threadId: "thread_a" },
    },
    {
      call: () => state.updateMemoryForThread(store, "thread_a", "memory_1", { text: "Edited" }),
      expected: { operation: "edit", controlKind: "memory_edit", threadId: "thread_a", memoryId: "memory_1" },
    },
    {
      call: () => state.deleteMemoryForThread(store, "thread_a", "memory_1", {}),
      expected: { operation: "delete", controlKind: "memory_delete", threadId: "thread_a", memoryId: "memory_1" },
    },
    {
      call: () => state.rememberForAgentId(store, "agent_a", { text: "Remember", thread_id: "thread_a" }),
      expected: { operation: "write", controlKind: "memory_write", agentId: "agent_a" },
    },
    {
      call: () => state.setMemoryPolicyForAgent(store, "agent_a", { thread_id: "thread_a" }),
      expected: { operation: "policy_update", controlKind: "memory_policy_update", agentId: "agent_a" },
    },
    {
      call: () => state.updateMemoryForAgentId(store, "agent_a", "memory_1", { thread_id: "thread_a" }),
      expected: { operation: "edit", controlKind: "memory_edit", agentId: "agent_a", memoryId: "memory_1" },
    },
    {
      call: () => state.deleteMemoryForAgentId(store, "agent_a", "memory_1", { thread_id: "thread_a" }),
      expected: { operation: "delete", controlKind: "memory_delete", agentId: "agent_a", memoryId: "memory_1" },
    },
    {
      call: () => state.updateMemoryRecord(store, "memory_1", { text: "Edited" }),
      expected: { operation: "edit", controlKind: "memory_edit", memoryId: "memory_1" },
    },
    {
      call: () => state.deleteMemoryRecord(store, "memory_1", {}),
      expected: { operation: "delete", controlKind: "memory_delete", memoryId: "memory_1" },
    },
  ];

  for (const { call, expected } of cases) {
    assert.throws(
      call,
      (error) => {
        assertThreadMemoryRustCoreRequired(error, expected);
        return true;
      },
    );
  }

  assert.deepEqual(calls, []);
});

test("route-facing memory read projections fail closed before JS memory store readback", () => {
  const { calls, state, store } = createHarness();

  const cases = [
    {
      call: () => state.publicListMemoryForThread(store, "thread_a", { query: "deploy" }),
      expected: { operation: "read_projection", controlKind: "memory_read_projection", threadId: "thread_a" },
    },
    {
      call: () => state.publicMemoryPolicyForThread(store, "thread_a", {}),
      expected: { operation: "policy_projection", controlKind: "memory_policy_projection", threadId: "thread_a" },
    },
    {
      call: () => state.publicMemoryPathForThread(store, "thread_a", {}),
      expected: { operation: "path_projection", controlKind: "memory_path_projection", threadId: "thread_a" },
    },
    {
      call: () => state.publicListMemoryForAgent(store, "agent_a", { query: "deploy" }),
      expected: { operation: "read_projection", controlKind: "memory_read_projection", agentId: "agent_a" },
    },
    {
      call: () => state.publicMemoryPolicyForAgent(store, "agent_a", {}),
      expected: { operation: "policy_projection", controlKind: "memory_policy_projection", agentId: "agent_a" },
    },
    {
      call: () => state.publicMemoryPathForAgent(store, "agent_a", {}),
      expected: { operation: "path_projection", controlKind: "memory_path_projection", agentId: "agent_a" },
    },
    {
      call: () => state.publicMemoryProjectionForContext(store, { thread_id: "thread_a" }),
      expected: {
        operation: "read_projection",
        controlKind: "memory_read_projection",
        threadId: "thread_a",
        agentId: "agent_a",
      },
    },
    {
      call: () => state.publicMemoryStatus(store, { agent_id: "agent_a" }),
      expected: { operation: "status_projection", controlKind: "memory_status_projection", agentId: "agent_a" },
    },
    {
      call: () => state.publicMemoryPolicyForContext(store, { thread_id: "thread_a" }),
      expected: {
        operation: "policy_projection",
        controlKind: "memory_policy_projection",
        threadId: "thread_a",
        agentId: "agent_a",
      },
    },
    {
      call: () => state.publicMemoryPathForContext(store, { thread_id: "thread_a" }),
      expected: {
        operation: "path_projection",
        controlKind: "memory_path_projection",
        threadId: "thread_a",
        agentId: "agent_a",
      },
    },
    {
      call: () => state.publicValidateMemory(store, { thread_id: "thread_a" }),
      expected: {
        operation: "validate_projection",
        controlKind: "memory_validate_projection",
        threadId: "thread_a",
        agentId: "agent_a",
      },
    },
  ];

  for (const { call, expected } of cases) {
    assert.throws(
      call,
      (error) => {
        assertThreadMemoryRustCoreRequired(error, expected);
        return true;
      },
    );
  }

  assert.deepEqual(calls, []);
});

test("thread memory status and validation facades fail closed before event append or Rust planning", () => {
  const { calls, state, store } = createHarness();

  assert.throws(
    () => state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1"),
    (error) => {
      assertThreadMemoryRustCoreRequired(error, {
        operation: "status",
        controlKind: "memory_status",
        threadId: "thread_a",
      });
      return true;
    },
  );

  assert.throws(
    () => state.validateThreadMemory(store, "thread_a", { source: "validate_test" }, "memory.validation.v1"),
    (error) => {
      assertThreadMemoryRustCoreRequired(error, {
        operation: "validate",
        controlKind: "memory_validate",
        threadId: "thread_a",
      });
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("thread memory direct control event facade fails closed before appendRuntimeEvent", () => {
  const { calls, state, store } = createHarness();

  assert.throws(
    () => state.appendThreadMemoryControlEvent(store, {
      threadId: "thread_a",
      agent: { id: "agent_a", cwd: "/workspace" },
      request: { source: "test" },
      controlKind: "memory_status",
      sourceEventKind: "OperatorControl.Memory",
      eventKind: "memory.status",
      componentKind: "memory_policy",
      workflowNodeId: "runtime.memory-manager",
      payloadSchemaVersion: "memory.status.v1",
      status: "completed",
      payload: {},
    }),
    (error) => {
      assertThreadMemoryRustCoreRequired(error, {
        operation: "memory_status",
        controlKind: "memory_status",
        threadId: "thread_a",
      });
      return true;
    },
  );

  assert.deepEqual(calls, []);
});
