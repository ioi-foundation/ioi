import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlManagedSessionForThread,
  inspectManagedSessionsForThread,
} from "./managed-session-state.mjs";

function fakeStore({ sessions = [], contextPolicyCore = {}, appendRuntimeEvent = null } = {}) {
  const calls = [];
  return {
    calls,
    stateDir: "/runtime-state",
    contextPolicyCore,
    managedSessionsForThread(thread_id) {
      calls.push({ operation: "managed_sessions_for_thread", thread_id });
      return sessions;
    },
    appendRuntimeEvent(event) {
      calls.push({ operation: "append_runtime_event", event });
      if (appendRuntimeEvent) return appendRuntimeEvent(event);
      return { admitted: true, event };
    },
    agentForThread(thread_id) {
      assert.fail(`managed session state must not read JS agent truth: ${thread_id}`);
    },
    assertRuntimeBridgeAvailable(input) {
      assert.fail(`managed session state must not assert JS bridge availability: ${JSON.stringify(input)}`);
    },
    runtimeBridge: {
      inspectThread(input) {
        assert.fail(`managed session inspection bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
      controlThread(input) {
        assert.fail(`managed session control bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  };
}

function assertNoRetiredManagedSessionDetailAliases(details = {}) {
  for (const key of [
    "threadId",
    "operationKind",
    "rustCoreBoundary",
    "evidenceRefs",
    "managedSessionId",
    "sessionId",
    "retiredAliases",
  ]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

test("managed session inspection returns Rust daemon-core projection without JS bridge readback", async () => {
  let captured = null;
  const store = fakeStore({
    sessions: [
      {
        managed_session_id: "sandbox_browser:1",
        thread_id: "thread_runtime",
        status: "waiting_for_user",
        control_state: "observe",
      },
    ],
    contextPolicyCore: {
      projectRuntimeManagedSessionProjection(request) {
        captured = request;
        return {
          status: "projected",
          operation: "managed_session_inspection",
          operation_kind: "managed_session.inspect",
          projection_kind: "list",
          thread_id: "thread_runtime",
          projection: [
            {
              managed_session_id: "sandbox_browser:1",
              thread_id: "thread_runtime",
              control_state: "observe",
            },
          ],
          record_count: 1,
          evidence_refs: ["runtime_managed_session_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_managed_session_projection_list"],
        };
      },
    },
  });

  const result = await inspectManagedSessionsForThread(store, "thread_runtime", {
    projection_kind: "list",
  });

  assert.equal(captured.operation, "managed_session_inspection");
  assert.equal(captured.operation_kind, "managed_session.inspect");
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_runtime");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.deepEqual(captured.evidence_refs, [
    "runtime_managed_session_projection_rust_owned",
    "managed_session_inspection_js_facade_retired",
    "agentgres_managed_session_truth_required",
  ]);
  assert.equal(result.operation_kind, "managed_session.inspect");
  assert.equal(result.projection[0].managed_session_id, "sandbox_browser:1");
  assert.deepEqual(store.calls, []);
});

test("managed session inspection fails closed before JS fallback projection when Rust projector is missing", async () => {
  const store = fakeStore();

  await assert.rejects(
    inspectManagedSessionsForThread(store, "thread_runtime", {
      projection_kind: "summary",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_managed_session_projection_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.managed_session_control");
      assert.equal(error.details.operation, "managed_session_inspection");
      assert.equal(error.details.operation_kind, "managed_session.inspect");
      assert.equal(error.details.projection_kind, "summary");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_managed_session_projection_rust_owned",
        "managed_session_inspection_js_facade_retired",
        "agentgres_managed_session_truth_required",
      ]);
      assertNoRetiredManagedSessionDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("managed session control uses Rust planning and runtime event admission", async () => {
  let captured = null;
  const plannedEvent = {
    event_stream_id: "thread_runtime:events",
    thread_id: "thread_runtime",
    event_kind: "managed_session.controlled",
    source_event_kind: "OperatorControl.ManagedSessionControl",
    payload: {
      managed_session_id: "sandbox_browser:1",
      control_state: "take_over",
    },
  };
  const store = fakeStore({
    sessions: [
      {
        managed_session_id: "sandbox_browser:1",
        thread_id: "thread_runtime",
        control_state: "observe",
      },
    ],
    contextPolicyCore: {
      planRuntimeManagedSessionControl(request) {
        captured = request;
        return {
          status: "planned",
          operation: "managed_session_control",
          operation_kind: "managed_session.control",
          thread_id: "thread_runtime",
          managed_session_id: "sandbox_browser:1",
          control_state: "take_over",
          event: plannedEvent,
          receipt_refs: ["receipt_managed_session_control"],
          policy_decision_refs: ["policy_managed_session_control"],
          evidence_refs: ["runtime_managed_session_control_rust_owned"],
        };
      },
    },
  });

  const result = await controlManagedSessionForThread(store, "thread_runtime", {
    managed_session_id: "sandbox_browser:1",
    control_state: "take_over",
    reason: "operator takeover",
    workspace_root: "/workspace/project",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  });

  assert.equal(captured.operation, "managed_session_control");
  assert.equal(captured.operation_kind, "managed_session.control");
  assert.equal(captured.thread_id, "thread_runtime");
  assert.equal(captured.event_stream_id, "thread_runtime:events");
  assert.equal(captured.managed_session_id, "sandbox_browser:1");
  assert.equal(captured.control_state, "take_over");
  assert.equal(captured.managed_session.control_state, "observe");
  assert.deepEqual(captured.request.receipt_refs, ["receipt_request"]);
  assert.deepEqual(captured.receipt_refs, ["receipt_request"]);
  assert.deepEqual(captured.evidence_refs, [
    "runtime_managed_session_control_rust_owned",
    "runtime_managed_session_control_event_rust_owned",
    "managed_session_control_js_facade_retired",
    "agentgres_managed_session_truth_required",
  ]);
  assert.deepEqual(store.calls, [
    { operation: "managed_sessions_for_thread", thread_id: "thread_runtime" },
    { operation: "append_runtime_event", event: plannedEvent },
  ]);
  assert.deepEqual(result, { admitted: true, event: plannedEvent });
});

test("managed session control fails closed before Rust planning or event append when planner is missing", async () => {
  const store = fakeStore();

  await assert.rejects(
    controlManagedSessionForThread(store, "thread_runtime", {
      managed_session_id: "sandbox_browser:1",
      control_state: "take_over",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_managed_session_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.managed_session_control");
      assert.equal(error.details.operation, "managed_session_control");
      assert.equal(error.details.operation_kind, "managed_session.control");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.equal(error.details.managed_session_id, "sandbox_browser:1");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_managed_session_control_rust_owned",
        "runtime_managed_session_control_event_rust_owned",
        "managed_session_control_js_facade_retired",
        "agentgres_managed_session_truth_required",
      ]);
      assertNoRetiredManagedSessionDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("managed session control ignores retired request aliases before Rust planning", async () => {
  let planned = false;
  const store = fakeStore({
    contextPolicyCore: {
      planRuntimeManagedSessionControl() {
        planned = true;
        assert.fail("retired managed-session aliases must not reach Rust control planning");
      },
    },
  });

  await assert.rejects(
    controlManagedSessionForThread(store, "thread_runtime", {
      managedSessionId: "sandbox_browser:legacy",
      action: "take_over",
      createdAt: "2026-06-12T00:00:00.000Z",
      requestHash: "retired_hash",
    }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime_managed_session_control_id_required");
      assert.equal(error.details.thread_id, "thread_runtime");
      assertNoRetiredManagedSessionDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(planned, false);
  assert.deepEqual(store.calls, []);
});
