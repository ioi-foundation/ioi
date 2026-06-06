import assert from "node:assert/strict";
import test from "node:test";

import { createThreadForkState } from "./thread-fork-state.mjs";

function createHarness({ duplicate = null } = {}) {
  const calls = [];
  const events = [];
  const sourceThread = {
    thread_id: "thread_a",
    agent_id: "agent_a",
    session_id: "session_a",
    workspace: "/workspace",
    model_route: "route.local-first",
    latest_seq: 42,
    latest_turn_id: "turn_a",
  };
  const forkThread = {
    thread_id: "thread_fork",
    agent_id: "agent_fork",
    session_id: "session_fork",
  };
  const state = createThreadForkState({
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    fixtureProfileForAgent: () => "fixture.test",
    operatorControlSource: (source) => source ?? "operator",
    optionalString: (value) => (typeof value === "string" && value ? value : undefined),
  });
  const store = {
    defaultCwd: "/default",
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return { id: "agent_a", cwd: "/workspace" };
    },
    appendRuntimeEvent(event) {
      events.push(event);
      calls.push({ type: "appendRuntimeEvent", event });
      return event;
    },
    createAgent(options) {
      calls.push({ type: "createAgent", options });
      return { id: "agent_fork", cwd: options.local.cwd };
    },
    getThread(threadId) {
      calls.push({ type: "getThread", threadId });
      if (threadId === "thread_a") return sourceThread;
      if (threadId === "thread_fork") return forkThread;
      return { thread_id: threadId, agent_id: `agent_${threadId}` };
    },
    runtimeEventStream() {
      return {
        idempotency: new Map(duplicate ? [["fork-key", duplicate]] : []),
      };
    },
    threadForAgent(agent) {
      calls.push({ type: "threadForAgent", agentId: agent.id });
      return forkThread;
    },
  };
  return { calls, events, state, store };
}

test("thread fork state returns idempotent duplicate fork results", () => {
  const { calls, state, store } = createHarness({
    duplicate: {
      payload_summary: {
        fork_thread_id: "thread_fork",
        source_latest_seq: 39,
      },
    },
  });

  const result = state.forkThread(store, "thread_a", { idempotency_key: "fork-key" });

  assert.equal(result.thread_id, "thread_fork");
  assert.equal(result.source_thread_id, "thread_a");
  assert.equal(result.forked_from_seq, 39);
  assert.equal(calls.some((call) => call.type === "createAgent"), false);
});

test("thread fork state creates fork agents and emits fork events", () => {
  const { calls, events, state, store } = createHarness();

  const result = state.forkThread(store, "thread_a", {
    source: "studio",
    actor: "operator_one",
    reason: "branch experiment",
    idempotency_key: "fork-key",
    options: {
      local: { cwd: "/override" },
      model: { id: "route.override" },
    },
    workflow_graph_id: "graph",
    workflow_node_id: "node.fork",
  });

  assert.equal(result.thread_id, "thread_fork");
  assert.equal(result.source_thread_id, "thread_a");
  assert.equal(result.forked_from_seq, 42);
  assert.deepEqual(calls.find((call) => call.type === "createAgent").options, {
    local: { cwd: "/override" },
    model: { id: "route.override" },
  });
  assert.equal(events.length, 1);
  assert.equal(events[0].event_kind, "thread.forked");
  assert.equal(events[0].idempotency_key, "fork-key");
  assert.equal(events[0].workflow_graph_id, "graph");
  assert.equal(events[0].workflow_node_id, "node.fork");
  assert.equal(events[0].payload.reason, "branch experiment");
  assert.equal(events[0].payload.requested_by, "operator_one");
  assert.equal(events[0].fixture_profile, "fixture.test");
});

test("thread fork state ignores retired request identity aliases", () => {
  const { calls, events, state, store } = createHarness({
    duplicate: {
      payload_summary: {
        fork_thread_id: "thread_duplicate",
        source_latest_seq: 39,
      },
    },
  });

  const result = state.forkThread(store, "thread_a", {
    idempotencyKey: "fork-key",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
  });

  assert.equal(result.thread_id, "thread_fork");
  assert.equal(result.forked_from_seq, 42);
  assert.equal(calls.some((call) => call.type === "createAgent"), true);
  assert.equal(events.length, 1);
  assert.equal(events[0].workflow_graph_id, null);
  assert.equal(events[0].workflow_node_id, "runtime.thread-fork");
  assert.equal(events[0].idempotency_key, "thread:thread_a:operator.fork:thread_fork");
});

test("thread fork state defaults fork options and idempotency", () => {
  const { calls, events, state, store } = createHarness();

  state.forkThread(store, "thread_a", {});

  assert.deepEqual(calls.find((call) => call.type === "createAgent").options, {
    local: { cwd: "/workspace" },
    model: { id: "route.local-first" },
  });
  assert.equal(events[0].idempotency_key, "thread:thread_a:operator.fork:thread_fork");
  assert.equal(events[0].source, "operator");
  assert.equal(events[0].payload.reason, "operator requested thread fork");
});
