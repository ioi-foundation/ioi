import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlRuntimeBridgeThread,
  createRuntimeBridgeThread,
  createRuntimeBridgeTurn,
} from "./runtime-bridge-thread.mjs";

const retiredRuntimeBridgeErrorDetailAliasKeys = [
  "threadId",
  "runId",
  "turnId",
  "sessionId",
  "runtimeProfile",
  "operationKind",
  "expectedOperationKind",
];

function assertNoRetiredRuntimeBridgeErrorDetailAliases(details) {
  for (const key of retiredRuntimeBridgeErrorDetailAliasKeys) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

function assertRuntimeBridgeThreadRustCoreRequired(error, {
  operation,
  operationKind,
  runtimeProfile,
  evidenceRef,
  threadId,
  agentId,
  action,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_bridge_thread_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.bridge_thread");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.runtime_profile, runtimeProfile);
  if (threadId) assert.equal(error.details.thread_id, threadId);
  if (agentId) assert.equal(error.details.agent_id, agentId);
  if (action) assert.equal(error.details.action, action);
  assert.equal(error.details.evidence_refs.includes(evidenceRef), true);
  assertNoRetiredRuntimeBridgeErrorDetailAliases(error.details);
  return true;
}

function deps() {
  return {
    runtimeError: (input) => {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
  };
}

test("runtime bridge thread creation fails closed before JS bridge dispatch and agent persistence", async () => {
  const store = { calls: [], agents: new Map() };

  await assert.rejects(
    createRuntimeBridgeThread(store, {
      request: { runtime_profile: "runtime_service" },
      options: { local: { cwd: "/workspace" } },
      runtimeProfile: "runtime_service",
    }, deps()),
    (error) => {
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_thread_start",
        operationKind: "thread.runtime_bridge.start",
        runtimeProfile: "runtime_service",
        evidenceRef: "runtime_bridge_thread_start_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "create_agent"), false);
  assert.equal(store.calls.some((call) => call.operation === "start_thread"), false);
  assert.equal(
    store.calls.some((call) => call.operation === "plan_runtime_bridge_thread_start_agent_state_update"),
    false,
  );
  assert.equal(store.calls.some((call) => call.operation === "write_agent"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_event"), false);
  assert.equal(store.agents.size, 0);
});

test("runtime bridge turn creation fails closed before JS bridge dispatch and run persistence", async () => {
  const store = { calls: [], runs: new Map() };
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  await assert.rejects(
    createRuntimeBridgeTurn(store, {
      agent,
      threadId: "thread_agent_runtime",
      request: { prompt: "hello", max_steps: 2, options: { maxSteps: 4 } },
      diagnosticsFeedback: { injectionId: "diag_1" },
    }, deps()),
    (error) => {
      assert.equal(error.details.thread_id, "thread_agent_runtime");
      assert.equal(error.details.agent_id, "agent_runtime");
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_turn_submit",
        operationKind: "turn.runtime_bridge.submit",
        runtimeProfile: "runtime_service",
        evidenceRef: "runtime_bridge_turn_submit_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "submit_turn"), false);
  assert.equal(store.calls.some((call) => call.operation === "register_in_flight"), false);
  assert.equal(store.calls.some((call) => call.operation === "unregister_in_flight"), false);
  assert.equal(store.calls.some((call) => call.operation === "append_event"), false);
  assert.equal(
    store.calls.some((call) => call.operation === "plan_runtime_bridge_turn_run_state_update"),
    false,
  );
  assert.equal(store.calls.some((call) => call.operation === "write_run"), false);
  assert.equal(store.runs.size, 0);
  assert.equal(store.calls.some((call) => call.operation === "append_operation"), false);
});

test("runtime bridge thread control fails closed before JS bridge dispatch", async () => {
  const store = { calls: [] };
  const agent = {
    id: "agent_runtime",
    cwd: "/workspace",
    runtimeProfile: "runtime_service",
    runtimeSessionId: "session_runtime",
  };

  await assert.rejects(
    controlRuntimeBridgeThread(store, {
      agent,
      threadId: "thread_agent_runtime",
      action: "resume",
      reason: "operator requested resume",
    }, deps()),
    (error) => {
      return assertRuntimeBridgeThreadRustCoreRequired(error, {
        operation: "runtime_bridge_thread_control",
        operationKind: "thread.runtime_bridge.control",
        runtimeProfile: "runtime_service",
        threadId: "thread_agent_runtime",
        agentId: "agent_runtime",
        action: "resume",
        evidenceRef: "runtime_bridge_thread_control_js_facade_retired",
      });
    },
  );
  assert.equal(store.calls.some((call) => call.operation === "assert_bridge"), false);
  assert.equal(store.calls.some((call) => call.operation === "control_thread"), false);
});
