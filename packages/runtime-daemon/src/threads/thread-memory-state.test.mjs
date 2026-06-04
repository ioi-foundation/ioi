import assert from "node:assert/strict";
import test from "node:test";

import { createThreadMemoryState } from "./thread-memory-state.mjs";

function createHarness() {
  const calls = [];
  const agents = new Map([
    ["agent_a", { id: "agent_a", cwd: "/workspace" }],
  ]);
  const state = createThreadMemoryState({
    agentIdForThread: (threadId) => threadId.replace("thread_", "agent_"),
    memoryListFilters: (options = {}) => ({
      query: options.query ?? null,
      scope: options.scope ?? null,
    }),
    memoryPolicyOverrides: (policy = {}) => ({ ...policy, normalized: true }),
    memoryStatusForProjection: (projection = {}) => ({
      status: projection.records?.length ? "ready" : "empty",
      record_count: projection.records?.length ?? 0,
    }),
    optionalString: (value) => (typeof value === "string" && value ? value : undefined),
    threadIdForAgent: (agentId) => agentId.replace("agent_", "thread_"),
    validateMemoryProjection: (projection = {}) => ({
      ok: true,
      record_count: projection.records?.length ?? 0,
    }),
  });
  const store = {
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
      calls.push({ type: "recordThreadMemoryMutation", threadId, mutation, body, operation });
      return { recorded: true, mutation, operation };
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
    },
  };
  return { calls, state, store };
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
  assert.deepEqual(calls.filter((call) => call.type === "projection").map((call) => call.threadId), [
    "thread_a",
    "thread_a",
  ]);
});

test("thread memory state handles policies, paths, status, and validation", () => {
  const { state, store } = createHarness();

  assert.equal(state.memoryPolicyForThread(store, "thread_a").id, "policy_thread_a");
  assert.equal(state.memoryPathForAgent(store, "agent_a").recordsPath, "/workspace/thread_a/memory");
  assert.deepEqual(state.memoryStatus(store, { thread_id: "thread_a" }), {
    status: "ready",
    record_count: 1,
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

  assert.deepEqual(state.setMemoryPolicyForThread(store, "thread_a", { policy: { readOnly: true } }), {
    recorded: true,
    mutation: { policy: { id: "policy_thread_a" } },
    operation: "policy_update",
  });
  assert.deepEqual(state.setMemoryPolicyForAgent(store, "agent_a", { read_only: true }), {
    policy: { id: "policy_thread_a" },
  });
  const policyCalls = calls.filter((call) => call.type === "setPolicy").map((call) => call.input);
  assert.equal(policyCalls[0].updates.normalized, true);
  assert.equal(policyCalls[0].updates.readOnly, true);
  assert.equal(policyCalls[1].updates.read_only, true);
});
