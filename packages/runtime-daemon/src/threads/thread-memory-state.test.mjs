import assert from "node:assert/strict";
import test from "node:test";

import { createThreadMemoryState } from "./thread-memory-state.mjs";

function publicMemoryProjectionForRequest(request = {}, store = {}) {
  const records = [...(store.memory?.records?.values?.() ?? [])].filter(
    (record) =>
      record.status !== "deleted" &&
      (!request.thread_id || record.thread_id === request.thread_id) &&
      (!request.agent_id || record.agent_id === request.agent_id),
  ).map((record) => ({ id: record.id, fact: record.fact }));
  const projection = {
    schema_version: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_projection",
    agent_id: request.agent_id ?? null,
    thread_id: request.thread_id ?? null,
    workspace: request.workspace_root ?? null,
    policy: {
      id: `policy_${request.thread_id ?? "runtime"}`,
      injection_enabled: true,
    },
    paths: {
      records_path: `${request.state_dir}/memory-records`,
      policies_path: `${request.state_dir}/memory-policies`,
      effective_policy_id: `policy_${request.thread_id ?? "runtime"}`,
    },
    filters: request.filters ?? {},
    records,
    total_matches: records.length,
    state_dir_replay_required: true,
  };
  switch (request.projection_kind) {
    case "records":
      return projection;
    case "policy":
      return projection.policy;
    case "path":
      return projection.paths;
    case "status":
      return {
        object: "ioi.runtime_memory_manager_status",
        status: "ready",
        record_count: projection.records.length,
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        workspace: request.workspace_root ?? null,
      };
    case "validation":
      return {
        object: "ioi.runtime_memory_manager_validation",
        ok: true,
        record_count: projection.records.length,
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        workspace: request.workspace_root ?? null,
      };
    default:
      return null;
  }
}

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
  let store;
  store = {
    agents,
    stateDir: "/runtime-state",
    contextPolicyCore:
      Object.hasOwn(options, "contextPolicyCore")
        ? options.contextPolicyCore
        : {
            planThreadMemoryAgentStateUpdate(request = {}) {
              calls.push({ type: "planThreadMemoryAgentStateUpdate", input: request });
              return {
                status: "planned",
                operation_kind: `thread.${request.control_kind}`,
                agent: { ...request.agent, updatedAt: request.created_at },
              };
            },
            planRuntimeMemoryControl(request = {}) {
              calls.push({ type: "planRuntimeMemoryControl", input: request });
              const isPolicy = request.operation_kind === "memory.policy";
              const isEvent = ["memory.status", "memory.validate"].includes(request.operation_kind);
              const stateId =
                request.memory_id ??
                (isEvent
                  ? `event_${request.operation}`
                  : isPolicy ? "memory_policy_thread_a" : "memory_new");
              const payload = isEvent
                ? {
                    event_id: stateId,
                    event_stream_id: request.request?.event_stream_id,
                    thread_id: request.thread_id,
                    agent_id: request.agent_id,
                    turn_id: request.request?.turn_id ?? null,
                    item_id: `turn_latest:item:memory:${request.operation}`,
                    idempotency_key: `thread:${request.thread_id}:${request.operation_kind}:test`,
                    source: request.source,
                    source_event_kind: request.request?.source_event_kind,
                    event_kind: request.request?.event_kind,
                    status: request.request?.status,
                    component_kind: request.request?.component_kind,
                    workflow_node_id: request.request?.workflow_node_id,
                    payload_schema_version: request.request?.payload_schema_version,
                    payload: {
                      ...(request.request?.payload ?? {}),
                      operation: request.operation,
                      control_kind: request.request?.control_kind,
                    },
                    receipt_refs: [`receipt_${stateId}`],
                    policy_decision_refs: request.request?.policy_decision_refs ?? [],
                    evidence_refs: request.evidence_refs,
                  }
                : isPolicy
                  ? {
                      schema_version: "ioi.agent-runtime.memory-policy.v1",
                      object: "ioi.agent_memory_policy",
                    id: stateId,
                    target_type: request.target_type ?? "thread",
                    target_id: request.target_id ?? request.thread_id,
                    thread_id: request.thread_id,
                    agent_id: request.agent_id,
                    read_only: request.request?.policy?.read_only ?? request.request?.read_only ?? false,
                    receipt_refs: [`receipt_${stateId}`],
                  }
                : {
                    schema_version: "ioi.agent-runtime.memory.v1",
                    object: "ioi.agent_memory_record",
                    id: stateId,
                    thread_id: request.thread_id,
                    agent_id: request.agent_id,
                    workspace: request.workspace_root,
                    fact: request.request?.text ?? "",
                    status: request.operation_kind === "memory.delete" ? "deleted" : "active",
                    deleted_at: request.operation_kind === "memory.delete" ? request.now : null,
                    receipt_refs: [`receipt_${stateId}`],
                  };
              return {
                source: "rust_runtime_memory_control_command",
                status: "planned",
                operation: request.operation,
                operation_kind: request.operation_kind,
                memory_state_kind: isEvent ? "event" : isPolicy ? "policy" : "record",
                state_id: stateId,
                thread_id: request.thread_id,
                agent_id: request.agent_id,
                workspace_root: request.workspace_root,
                payload,
                receipt_refs: [`receipt_${stateId}`],
                evidence_refs: ["runtime_memory_control_rust_owned"],
              };
            },
            projectRuntimeMemoryProjection(request = {}) {
              calls.push({ type: "projectRuntimeMemoryProjection", input: request });
              return {
                source: "rust_runtime_memory_projection_command",
                projection_kind: request.projection_kind,
                operation_kind: request.operation_kind,
                projection: publicMemoryProjectionForRequest(request, store),
                record_count: 1,
                evidence_refs: ["runtime_memory_public_projection_rust_owned"],
                receipt_refs: [`receipt_runtime_memory_projection_${request.projection_kind}`],
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
    commitRuntimeMemoryState(request) {
      calls.push({ type: "commitRuntimeMemoryState", input: request });
      if (request.memory_state_kind === "record") {
        this.memory.records.set(request.state_id, request.payload);
      } else {
        this.memory.policies.set(request.state_id, request.payload);
      }
      return {
        source: "rust_agentgres_runtime_memory_state_commit_command",
        memory_state_kind: request.memory_state_kind,
        state_id: request.state_id,
        operation_kind: request.operation_kind,
        object_ref: `agentgres://runtime-state/memory/${request.memory_state_kind}/${request.state_id}`,
        payload_refs: [`payload://runtime/memory/${request.memory_state_kind}/${request.state_id}`],
        receipt_refs: request.receipt_refs,
        commit_hash: `sha256:${request.state_id}`,
        evidence_refs: ["rust_agentgres_runtime_memory_state_commit"],
      };
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
      records: new Map([
        [
          "memory_1",
          {
            id: "memory_1",
            thread_id: "thread_a",
            agent_id: "agent_a",
            workspace: "/workspace",
            fact: "Remember deploy",
            status: "active",
          },
        ],
      ]),
      policies: new Map(),
      load() {
        calls.push({ type: "memoryLoad" });
      },
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
        const records = [...this.records.values()].filter(
          (record) =>
            record.status !== "deleted" &&
            (!threadId || record.thread_id === threadId) &&
            (!agent?.id || record.agent_id === agent.id),
        ).map((record) => ({ id: record.id }));
        return {
          schema_version: "ioi.agent-runtime.memory.v1",
          object: "ioi.agent_memory_projection",
          agent_id: agent?.id ?? null,
          thread_id: threadId ?? null,
          workspace,
          policy: { id: `policy_${threadId ?? "runtime"}`, injection_enabled: true },
          paths: { records_path: `${workspace}/${threadId ?? "runtime"}/memory` },
          records,
          filters,
          total_matches: records.length,
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
  assert.deepEqual(error.details.evidence_refs, expected.evidenceRefs ?? [
    "runtime_thread_memory_control_js_facade_retired",
    "runtime_thread_memory_write_js_facade_retired",
    "runtime_thread_memory_policy_js_facade_retired",
    "runtime_memory_state_store_js_mutation_retired",
    "rust_daemon_core_thread_memory_control_required",
    "agentgres_thread_memory_state_truth_required",
  ]);
  assertNoRetiredDetailAliases(error.details);
}

test("thread memory state projects thread and agent memory", () => {
  const { calls, state, store } = createHarness();

  assert.deepEqual(state.listMemoryForThread(store, "thread_a", { query: "deploy" }), {
    schema_version: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_projection",
    agent_id: "agent_a",
    thread_id: "thread_a",
    workspace: "/workspace",
    policy: { id: "policy_thread_a", injection_enabled: true },
    paths: { records_path: "/workspace/thread_a/memory" },
    records: [{ id: "memory_1" }],
    filters: { query: "deploy", scope: null },
    total_matches: 1,
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

test("thread memory mutation and policy controls use Rust planning and Agentgres commits", () => {
  const { calls, state, store } = createHarness();

  const write = state.rememberForThread(store, "thread_a", {
    text: "Remember deploy",
    source: "operator_remember",
  });
  const edit = state.updateMemoryForThread(store, "thread_a", "memory_new", {
    text: "Edited deploy",
  });
  const policy = state.setMemoryPolicyForThread(store, "thread_a", {
    policy: { read_only: true },
  });
  const deleted = state.deleteMemoryForThread(store, "thread_a", "memory_new", {
    reason: "stale",
  });
  const agentWrite = state.rememberForAgentId(store, "agent_a", {
    text: "Remember agent deploy",
    thread_id: "thread_a",
  });
  const agentEdit = state.updateMemoryForAgentId(store, "agent_a", "memory_new", {
    text: "Edited agent deploy",
    thread_id: "thread_a",
  });
  const agentPolicy = state.setMemoryPolicyForAgent(store, "agent_a", {
    thread_id: "thread_a",
    target_type: "agent",
    target_id: "agent_a",
    policy: { read_only: false },
  });
  const agentDeleted = state.deleteMemoryForAgentId(store, "agent_a", "memory_new", {
    thread_id: "thread_a",
    reason: "stale_agent",
  });

  assert.equal(write.status, "committed");
  assert.equal(write.operation_kind, "memory.write");
  assert.equal(write.record.id, "memory_new");
  assert.equal(write.projection.records.some((record) => record.id === "memory_new"), true);
  assert.equal(edit.operation_kind, "memory.edit");
  assert.equal(edit.record.fact, "Edited deploy");
  assert.equal(policy.operation_kind, "memory.policy");
  assert.equal(policy.policy.read_only, true);
  assert.equal(deleted.operation_kind, "memory.delete");
  assert.equal(deleted.record.status, "deleted");
  assert.equal(
    deleted.projection.records.some((record) => record.id === "memory_new"),
    false,
  );
  assert.equal(agentWrite.operation_kind, "memory.write");
  assert.equal(agentWrite.agent_id, "agent_a");
  assert.equal(agentEdit.operation_kind, "memory.edit");
  assert.equal(agentEdit.record.fact, "Edited agent deploy");
  assert.equal(agentPolicy.operation_kind, "memory.policy");
  assert.equal(agentPolicy.policy.target_type, "agent");
  assert.equal(agentDeleted.operation_kind, "memory.delete");
  assert.equal(agentDeleted.record.status, "deleted");

  const planCalls = calls.filter((call) => call.type === "planRuntimeMemoryControl");
  assert.deepEqual(
    planCalls.map((call) => call.input.operation_kind),
    [
      "memory.write",
      "memory.edit",
      "memory.policy",
      "memory.delete",
      "memory.write",
      "memory.edit",
      "memory.policy",
      "memory.delete",
    ],
  );
  assert.ok(planCalls.every((call) => call.input.state_dir === "/runtime-state"));
  assert.ok(planCalls.every((call) => Object.hasOwn(call.input, "current_record") === false));
  assert.ok(planCalls.every((call) => Object.hasOwn(call.input, "current_policy") === false));
  assert.deepEqual(
    calls
      .filter((call) => call.type === "commitRuntimeMemoryState")
      .map((call) => call.input.operation_kind),
    [
      "memory.write",
      "memory.edit",
      "memory.policy",
      "memory.delete",
      "memory.write",
      "memory.edit",
      "memory.policy",
      "memory.delete",
    ],
  );
  assert.equal(
    calls.some((call) =>
      ["remember", "updateRecord", "deleteRecord", "setPolicy"].includes(call.type),
    ),
    false,
  );
  assert.ok(
    calls
      .filter((call) => call.type === "commitRuntimeMemoryState")
      .every((call) => call.input.schema_version === "ioi.runtime_memory_state_commit.v1"),
  );
});

test("thread memory mutation controls fail closed before JS store mutation without Rust planner", () => {
  const { calls, state, store } = createHarness({
    contextPolicyCore: {
      projectRuntimeMemoryProjection(request = {}) {
        calls.push({ type: "projectRuntimeMemoryProjection", input: request });
        return {
          projection_kind: request.projection_kind,
          operation_kind: request.operation_kind,
          projection: publicMemoryProjectionForRequest(request, store),
        };
      },
    },
  });

  assert.throws(
    () => state.updateMemoryRecord(store, "memory_1", { text: "Edited" }),
    (error) => {
      assertThreadMemoryRustCoreRequired(error, {
        operation: "edit",
        controlKind: "memory.edit",
        threadId: null,
        agentId: null,
        memoryId: "memory_1",
      });
      return true;
    },
  );

  assert.equal(
    calls.some((call) =>
      ["remember", "updateRecord", "deleteRecord", "setPolicy", "commitRuntimeMemoryState"].includes(call.type),
    ),
    false,
  );
});

test("route-facing memory read projections return Rust daemon-core projections", () => {
  const { calls, state, store } = createHarness();

  assert.equal(
    state.publicListMemoryForThread(store, "thread_a", { query: "deploy" }).records[0].id,
    "memory_1",
  );
  assert.equal(state.publicMemoryPolicyForThread(store, "thread_a", {}).id, "policy_thread_a");
  assert.equal(
    state.publicMemoryPathForThread(store, "thread_a", {}).records_path,
    "/runtime-state/memory-records",
  );
  assert.equal(
    state.publicListMemoryForAgent(store, "agent_a", { query: "deploy" }).records[0].id,
    "memory_1",
  );
  assert.equal(state.publicMemoryPolicyForAgent(store, "agent_a", {}).id, "policy_thread_a");
  assert.equal(
    state.publicMemoryPathForAgent(store, "agent_a", {}).records_path,
    "/runtime-state/memory-records",
  );
  assert.equal(
    state.publicMemoryProjectionForContext(store, { thread_id: "thread_a" }).thread_id,
    "thread_a",
  );
  assert.deepEqual(state.publicMemoryStatus(store, { agent_id: "agent_a" }), {
    object: "ioi.runtime_memory_manager_status",
    status: "ready",
    record_count: 1,
    thread_id: "thread_a",
    agent_id: "agent_a",
    workspace: "/workspace",
  });
  assert.equal(state.publicMemoryPolicyForContext(store, { thread_id: "thread_a" }).id, "policy_thread_a");
  assert.equal(
    state.publicMemoryPathForContext(store, { thread_id: "thread_a" }).records_path,
    "/runtime-state/memory-records",
  );
  assert.deepEqual(state.publicValidateMemory(store, { thread_id: "thread_a" }), {
    object: "ioi.runtime_memory_manager_validation",
    ok: true,
    record_count: 1,
    thread_id: "thread_a",
    agent_id: "agent_a",
    workspace: "/workspace",
  });

  const projectionCalls = calls.filter((call) => call.type === "projectRuntimeMemoryProjection");
  assert.deepEqual(projectionCalls.map((call) => call.input.projection_kind), [
    "records",
    "policy",
    "path",
    "records",
    "policy",
    "path",
    "records",
    "status",
    "policy",
    "path",
    "validation",
  ]);
  assert.ok(
    projectionCalls.every(
      (call) => call.input.source === "runtime.thread_memory_state.public_projection",
    ),
  );
  assert.ok(
    projectionCalls.every((call) =>
      call.input.evidence_refs.includes("runtime_memory_public_projection_rust_owned"),
    ),
  );
  assert.equal(projectionCalls[0].input.operation, "runtime_memory_projection");
  assert.equal(projectionCalls[0].input.operation_kind, "runtime.memory_projection.records");
  assert.equal(projectionCalls[0].input.thread_id, "thread_a");
  assert.equal(projectionCalls[0].input.agent_id, "agent_a");
  assert.equal(projectionCalls[0].input.workspace_root, "/workspace");
  assert.equal(projectionCalls[0].input.state_dir, "/runtime-state");
  assert.deepEqual(projectionCalls[0].input.filters, { query: "deploy", scope: null });
  assert.ok(projectionCalls.every((call) => call.input.state_dir === "/runtime-state"));
  assert.ok(projectionCalls.every((call) => Object.hasOwn(call.input, "projection") === false));
  assert.equal(calls.some((call) => call.type === "projection"), false);
  assert.equal(Object.hasOwn(projectionCalls[0].input, "threadId"), false);
});

test("route-facing memory projections fail closed before JS readback when Rust projection is missing", () => {
  const { calls, state, store } = createHarness({ contextPolicyCore: null });

  assert.throws(
    () => state.publicListMemoryForThread(store, "thread_a", { query: "deploy" }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_public_memory_projection_rust_projection_missing");
      assert.equal(error.details.rust_core_boundary, "runtime.memory_projection");
      assert.equal(error.details.projection_kind, "records");
      assert.equal(error.details.thread_id, "thread_a");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_memory_public_projection_rust_owned",
        "agentgres_thread_memory_projection_truth_required",
      ]);
      return true;
    },
  );

  assert.equal(calls.some((call) => call.type === "appendRuntimeEvent"), false);
  assert.equal(calls.some((call) => call.type === "planRuntimeMemoryControl"), false);
  assert.equal(calls.some((call) => call.type === "commitRuntimeMemoryState"), false);
});

test("thread memory status, validation, and direct control events use Rust planning and runtime event admission", () => {
  const { calls, state, store } = createHarness();

  const status = state.recordThreadMemoryStatus(store, "thread_a", { source: "status_test" }, "memory.status.v1");
  const validation = state.validateThreadMemory(store, "thread_a", { source: "validate_test" }, "memory.validation.v1");
  const direct = state.appendThreadMemoryControlEvent(store, {
    threadId: "thread_a",
    agent: { id: "agent_a", cwd: "/workspace" },
    request: { source: "direct_status_test" },
    controlKind: "memory_status",
    sourceEventKind: "OperatorControl.MemoryStatus",
    eventKind: "memory.status",
    componentKind: "memory_manager",
    workflowNodeId: "runtime.memory-manager.status",
    payloadSchemaVersion: "memory.status.v1",
    status: "completed",
    payload: { status: "ready", record_count: 1 },
  });

  assert.equal(status.event_kind, "memory.status");
  assert.equal(status.payload.record_count, 1);
  assert.equal(validation.event_kind, "memory.validate");
  assert.equal(validation.payload.ok, true);
  assert.equal(direct.event_kind, "memory.status");
  assert.deepEqual(
    calls
      .filter((call) => call.type === "planRuntimeMemoryControl")
      .map((call) => call.input.operation_kind),
    ["memory.status", "memory.validate", "memory.status"],
  );
  assert.deepEqual(
    calls
      .filter((call) => call.type === "appendRuntimeEvent")
      .map((call) => call.event.event_kind),
    ["memory.status", "memory.validate", "memory.status"],
  );
  assert.equal(calls.some((call) => call.type === "commitRuntimeMemoryState"), false);
  assert.equal(calls.some((call) => call.type === "writeAgent"), false);
});

test("thread memory direct control event fails closed before appendRuntimeEvent without Rust planning", () => {
  const { calls, state, store } = createHarness({ contextPolicyCore: null });

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
        operation: "status",
        controlKind: "memory.status",
        threadId: "thread_a",
        agentId: "agent_a",
        evidenceRefs: [
          "runtime_memory_status_control_rust_owned",
          "runtime_memory_control_event_rust_owned",
          "runtime_memory_status_validation_control_rust_owned",
          "runtime_memory_status_validation_js_facade_retired",
          "agentgres_runtime_thread_event_truth_required",
        ],
      });
      return true;
    },
  );

  assert.equal(calls.some((call) => call.type === "appendRuntimeEvent"), false);
  assert.equal(calls.some((call) => call.type === "planRuntimeMemoryControl"), false);
  assert.equal(calls.some((call) => call.type === "commitRuntimeMemoryState"), false);
});
