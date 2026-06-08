import assert from "node:assert/strict";
import test from "node:test";

import { createThreadForkState } from "./thread-fork-state.mjs";

function createHarness() {
  const calls = [];
  const state = createThreadForkState();
  const store = {
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return { id: "agent_a", cwd: "/workspace" };
    },
    appendRuntimeEvent(event) {
      calls.push({ type: "appendRuntimeEvent", event });
      return event;
    },
    createAgent(options) {
      calls.push({ type: "createAgent", options });
      return { id: "agent_fork", cwd: options.local.cwd };
    },
    getThread(threadId) {
      calls.push({ type: "getThread", threadId });
      return { thread_id: threadId, agent_id: `agent_${threadId}` };
    },
    runtimeEventStream(streamId) {
      calls.push({ type: "runtimeEventStream", streamId });
      return { idempotency: new Map() };
    },
    threadForAgent(agent) {
      calls.push({ type: "threadForAgent", agentId: agent.id });
      return { thread_id: "thread_fork", agent_id: agent.id };
    },
  };
  return { calls, state, store };
}

function assertNoRetiredThreadForkDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "idempotencyKey",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, key), false, `retired detail alias ${key} must be absent`);
  }
}

test("thread fork mutation facade fails closed before JS fork lifecycle mutation", () => {
  const { calls, state, store } = createHarness();

  assert.throws(
    () =>
      state.forkThread(store, "thread_a", {
        idempotency_key: "fork-key",
        idempotencyKey: "retired-key",
        workflow_graph_id: "graph",
        workflowGraphId: "graph_retired",
        workflow_node_id: "node.fork",
        workflowNodeId: "node_retired",
        requestedBy: "operator_retired",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_thread_fork_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.thread_fork");
      assert.equal(error.details.operation, "thread_fork");
      assert.equal(error.details.operation_kind, "thread.fork");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.idempotency_key, "fork-key");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_thread_fork_js_facade_retired",
        "rust_daemon_core_thread_fork_required",
        "agentgres_thread_fork_state_truth_required",
      ]);
      assertNoRetiredThreadForkDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("thread fork missing idempotency still requires Rust daemon-core admission", () => {
  const { calls, state, store } = createHarness();

  assert.throws(
    () => state.forkThread(store, "thread_a", {}),
    (error) => {
      assert.equal(error.code, "runtime_thread_fork_rust_core_required");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(Object.hasOwn(error.details, "idempotency_key"), false);
      assertNoRetiredThreadForkDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});
