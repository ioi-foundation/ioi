import assert from "node:assert/strict";
import test from "node:test";

import { createThreadForkState } from "./thread-fork-state.mjs";

function plannedForkRecord() {
  return {
    source: "rust_runtime_thread_fork_control_api",
    backend: "rust_policy",
    object: "ioi.runtime_thread_fork_control",
    status: "planned",
    operation: "thread_fork",
    operation_kind: "thread.fork",
    thread_id: "thread_a",
    forked_thread_id: "thread_fork_123",
    agent_id: "agent_fork_123",
    source_agent_id: "agent_a",
    agent: {
      id: "agent_fork_123",
      cwd: "/workspace",
      parentThreadId: "thread_a",
      forkedFromThreadId: "thread_a",
      forkedFromAgentId: "agent_a",
    },
    thread: {
      thread_id: "thread_fork_123",
      agent_id: "agent_fork_123",
      event_stream_id: "thread_fork_123:events",
      parent_thread_id: "thread_a",
    },
    event: {
      event_stream_id: "thread_a:events",
      thread_id: "thread_a",
      event_kind: "thread.forked",
      source_event_kind: "OperatorControl.ThreadFork",
      receipt_refs: ["receipt_thread_fork_control"],
    },
    evidence_refs: [
      "runtime_thread_fork_control_rust_owned",
      "runtime_thread_fork_event_rust_owned",
      "runtime_thread_fork_state_dir_replay_required",
      "agentgres_thread_fork_state_truth_required",
    ],
    receipt_refs: ["receipt_thread_fork_control"],
    policy_decision_refs: ["policy_thread_fork_control_allow"],
  };
}

function createHarness({ plan = () => plannedForkRecord(), contextPolicyCore } = {}) {
  const calls = [];
  const state = createThreadForkState();
  const runner =
    contextPolicyCore ?? {
      planRuntimeThreadForkControl(request) {
        calls.push({ type: "planRuntimeThreadForkControl", request });
        return plan(request);
      },
    };
  const store = {
    stateDir: "/tmp/ioi-agentgres-thread-fork",
    agentForThread(threadId) {
      calls.push({ type: "agentForThread", threadId });
      return {
        id: "agent_a",
        cwd: "/workspace",
        createdAt: "2026-06-12T00:00:00.000Z",
      };
    },
    appendRuntimeEvent(event) {
      calls.push({ type: "appendRuntimeEvent", event });
      return event;
    },
    ensureThreadStartedEvent(agent) {
      calls.push({ type: "ensureThreadStartedEvent", agentId: agent.id });
      return { event_kind: "thread.started" };
    },
    threadForAgent(agent) {
      calls.push({ type: "threadForAgent", agentId: agent.id });
      if (agent.id === "agent_a") {
        return {
          thread_id: "thread_a",
          agent_id: "agent_a",
          event_stream_id: "thread_a:events",
        };
      }
      return {
        thread_id: "thread_fork_123",
        agent_id: agent.id,
        event_stream_id: "thread_fork_123:events",
      };
    },
    writeAgent(agent, reason) {
      calls.push({ type: "writeAgent", agent, reason });
      return agent;
    },
  };
  return { calls, contextPolicyCore: runner, state, store };
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

function assertNoRetiredThreadForkRequestAliases(request) {
  for (const key of [
    "idempotencyKey",
    "workflowGraphId",
    "workflowNodeId",
    "requestedBy",
  ]) {
    assert.equal(Object.hasOwn(request, key), false, `retired request alias ${key} must be absent`);
  }
}

test("thread fork uses Rust planning, Agentgres write, runtime-event admission, and Rust projection", async () => {
  const { calls, contextPolicyCore, state, store } = createHarness();

  const projection = await state.forkThread(store, "thread_a", {
    idempotency_key: "fork-key",
    workflow_graph_id: "graph",
    workflow_node_id: "node.fork",
    requested_by: "operator",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
    idempotencyKey: "retired-key",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
    requestedBy: "operator_retired",
  }, { contextPolicyCore });

  assert.deepEqual(projection, {
    thread_id: "thread_fork_123",
    agent_id: "agent_fork_123",
    event_stream_id: "thread_fork_123:events",
  });
  assert.deepEqual(calls.map((call) => call.type), [
    "planRuntimeThreadForkControl",
    "writeAgent",
    "ensureThreadStartedEvent",
    "threadForAgent",
    "appendRuntimeEvent",
  ]);
  const plannedRequest = calls.find((call) => call.type === "planRuntimeThreadForkControl").request;
  assert.equal(plannedRequest.operation, "thread_fork");
  assert.equal(plannedRequest.operation_kind, "thread.fork");
  assert.equal(plannedRequest.thread_id, "thread_a");
  assert.equal(plannedRequest.event_stream_id, "thread_a:events");
  assert.equal(plannedRequest.state_dir, "/tmp/ioi-agentgres-thread-fork");
  assert.equal(Object.hasOwn(plannedRequest, "source_agent"), false);
  assert.equal(Object.hasOwn(plannedRequest, "source_thread"), false);
  assert.equal(plannedRequest.request.idempotency_key, "fork-key");
  assert.equal(plannedRequest.request.workflow_graph_id, "graph");
  assert.equal(plannedRequest.request.workflow_node_id, "node.fork");
  assert.equal(plannedRequest.request.requested_by, "operator");
  assert.deepEqual(plannedRequest.receipt_refs, ["receipt_request"]);
  assert.deepEqual(plannedRequest.policy_decision_refs, ["policy_request"]);
  assertNoRetiredThreadForkRequestAliases(plannedRequest.request);
  const write = calls.find((call) => call.type === "writeAgent");
  assert.equal(write.agent.id, "agent_fork_123");
  assert.equal(write.reason, "thread.fork");
  const event = calls.find((call) => call.type === "appendRuntimeEvent").event;
  assert.equal(event.event_kind, "thread.forked");
  assert.equal(event.source_event_kind, "OperatorControl.ThreadFork");
});

test("thread fork request aliases stay retired after Rust planning", async () => {
  const { calls, contextPolicyCore, state, store } = createHarness();

  await state.forkThread(store, "thread_a", {
    idempotency_key: "fork-key",
    idempotencyKey: "retired-key",
    workflow_graph_id: "graph",
    workflowGraphId: "graph_retired",
    workflow_node_id: "node.fork",
    workflowNodeId: "node_retired",
    requested_by: "operator",
    requestedBy: "operator_retired",
  }, { contextPolicyCore });

  const plannedRequest = calls.find((call) => call.type === "planRuntimeThreadForkControl").request;
  assert.equal(plannedRequest.request.idempotency_key, "fork-key");
  assert.equal(plannedRequest.request.workflow_graph_id, "graph");
  assert.equal(plannedRequest.request.workflow_node_id, "node.fork");
  assert.equal(plannedRequest.request.requested_by, "operator");
  assert.equal(Object.hasOwn(plannedRequest, "source_agent"), false);
  assert.equal(Object.hasOwn(plannedRequest, "source_thread"), false);
  assertNoRetiredThreadForkRequestAliases(plannedRequest.request);
});

test("thread fork fails closed before source lookup when Rust planner is absent", async () => {
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
    threadForAgent(agent) {
      calls.push({ type: "threadForAgent", agentId: agent.id });
      return { thread_id: "thread_a", agent_id: agent.id };
    },
    writeAgent(agent) {
      calls.push({ type: "writeAgent", agent });
      return agent;
    },
  };

  await assert.rejects(
    () =>
      state.forkThread(store, "thread_a", {
        idempotency_key: "fork-key",
        idempotencyKey: "retired-key",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_thread_fork_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.thread_fork_control");
      assert.equal(error.details.operation, "thread_fork");
      assert.equal(error.details.operation_kind, "thread.fork");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.idempotency_key, "fork-key");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_thread_fork_control_rust_owned",
        "runtime_thread_fork_event_rust_owned",
        "runtime_thread_fork_state_dir_replay_required",
        "runtime_thread_fork_js_facade_retired",
        "agentgres_thread_fork_state_truth_required",
      ]);
      assertNoRetiredThreadForkDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("thread fork requires daemon state_dir before Rust planning or source lookup", async () => {
  const { calls, contextPolicyCore, state, store } = createHarness();
  delete store.stateDir;

  await assert.rejects(
    () =>
      state.forkThread(store, "thread_a", {
        idempotency_key: "fork-key",
      }, { contextPolicyCore }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_thread_fork_daemon_state_dir_required");
      assert.equal(error.details.rust_core_boundary, "runtime.thread_fork_control");
      assert.equal(error.details.thread_id, "thread_a");
      assert.equal(error.details.idempotency_key, "fork-key");
      assert.ok(
        error.details.evidence_refs.includes(
          "runtime_thread_fork_source_candidate_transport_retired",
        ),
      );
      assertNoRetiredThreadForkDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("thread fork rejects invalid Rust plans before Agentgres write or runtime-event admission", async () => {
  const { calls, contextPolicyCore, state, store } = createHarness({
    plan() {
      const record = plannedForkRecord();
      delete record.event;
      return record;
    },
  });

  await assert.rejects(
    () => state.forkThread(store, "thread_a", { idempotency_key: "fork-key" }, { contextPolicyCore }),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "runtime_thread_fork_control_event_invalid");
      assert.equal(error.details.operation_kind, "thread.fork");
      assert.equal(error.details.thread_id, "thread_a");
      return true;
    },
  );
  assert.deepEqual(calls.map((call) => call.type), [
    "planRuntimeThreadForkControl",
  ]);
});
