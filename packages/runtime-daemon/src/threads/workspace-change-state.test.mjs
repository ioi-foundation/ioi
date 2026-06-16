import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlWorkspaceChangeForThread,
  inspectWorkspaceChangeReviewsForThread,
} from "./workspace-change-state.mjs";

function fakeStore({
  appendRuntimeEvent = null,
  stateDir = "/runtime-state",
  workspaceChangeStateDir = null,
} = {}) {
  const calls = [];
  const store = {
    calls,
    stateDir,
    workspaceChangesForThread(thread_id) {
      assert.fail(`workspace change control must not read JS change candidates: ${thread_id}`);
    },
    appendRuntimeEvent(event) {
      calls.push({ operation: "append_runtime_event", event });
      if (appendRuntimeEvent) return appendRuntimeEvent(event);
      return { admitted: true, event };
    },
    agentForThread(thread_id) {
      assert.fail(`workspace change state must not read JS agent truth: ${thread_id}`);
    },
  };
  if (workspaceChangeStateDir !== null) {
    store.workspaceChanges = { stateDir: workspaceChangeStateDir };
  }
  return store;
}

function assertNoRetiredWorkspaceChangeDetailAliases(details = {}) {
  for (const key of [
    "threadId",
    "operationKind",
    "rustCoreBoundary",
    "evidenceRefs",
    "workspaceChangeId",
    "changeId",
    "toolId",
    "retiredAliases",
  ]) {
    assert.equal(Object.hasOwn(details, key), false);
  }
}

test("workspace change inspection returns Rust daemon-core projection without JS bridge readback", async () => {
  let captured = null;
  const contextPolicyCore = {
    projectRuntimeWorkspaceChangeProjection(request) {
      captured = request;
      return {
        status: "projected",
        operation: "workspace_change_inspection",
        operation_kind: "workspace_change.inspect",
        projection_kind: "list",
        thread_id: "thread_runtime",
        projection: [
          {
            workspace_change_id: "workspace_change:file:1",
            thread_id: "thread_runtime",
            review_state: "pending_review",
          },
        ],
        record_count: 1,
        evidence_refs: ["runtime_workspace_change_projection_rust_owned"],
        receipt_refs: ["receipt_runtime_workspace_change_projection_list"],
      };
    },
  };
  const store = fakeStore();

  const result = await inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {
    projection_kind: "list",
  }, { contextPolicyCore });

  assert.equal(captured.operation, "workspace_change_inspection");
  assert.equal(captured.operation_kind, "workspace_change.inspect");
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_runtime");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.deepEqual(captured.evidence_refs, [
    "runtime_workspace_change_projection_rust_owned",
    "workspace_change_inspection_js_facade_retired",
    "agentgres_workspace_change_truth_required",
  ]);
  assert.equal(result.operation_kind, "workspace_change.inspect");
  assert.equal(result.projection[0].workspace_change_id, "workspace_change:file:1");
  assert.deepEqual(store.calls, []);
});

test("workspace change inspection fails closed before JS fallback projection when Rust projector is missing", async () => {
  const store = fakeStore();

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {
      projection_kind: "summary",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_change_projection_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
      assert.equal(error.details.operation, "workspace_change_inspection");
      assert.equal(error.details.operation_kind, "workspace_change.inspect");
      assert.equal(error.details.projection_kind, "summary");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_workspace_change_projection_rust_owned",
        "workspace_change_inspection_js_facade_retired",
        "agentgres_workspace_change_truth_required",
      ]);
      assertNoRetiredWorkspaceChangeDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("workspace change inspection rejects retired per-family state_dir fallback before Rust projection", async () => {
  let projected = false;
  const contextPolicyCore = {
    projectRuntimeWorkspaceChangeProjection() {
      projected = true;
      assert.fail("workspace-change projection must not use per-family state_dir fallback");
    },
  };
  const store = fakeStore({
    stateDir: null,
    workspaceChangeStateDir: "/retired-workspace-change-state",
  });

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {
      projection_kind: "list",
    }, { contextPolicyCore }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_change_daemon_state_dir_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
      assert.equal(error.details.operation, "workspace_change_inspection");
      assert.equal(error.details.operation_kind, "workspace_change.inspect");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.equal(
        error.details.evidence_refs.includes("runtime_workspace_change_family_state_dir_fallback_retired"),
        true,
      );
      assertNoRetiredWorkspaceChangeDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(projected, false);
  assert.deepEqual(store.calls, []);
});

test("workspace change control uses Rust planning and runtime event admission", async () => {
  let captured = null;
  const plannedEvent = {
    event_stream_id: "thread_runtime:events",
    thread_id: "thread_runtime",
    event_kind: "workspace_change.controlled",
    source_event_kind: "OperatorControl.WorkspaceChangeControl",
    payload: {
      workspace_change_id: "workspace_change:file:1",
      control_state: "accept",
    },
  };
  const contextPolicyCore = {
    planRuntimeWorkspaceChangeControl(request) {
      captured = request;
      return {
        status: "planned",
        operation: "workspace_change_control",
        operation_kind: "workspace_change.control",
        thread_id: "thread_runtime",
        workspace_change_id: "workspace_change:file:1",
        control_state: "accept",
        event: plannedEvent,
        receipt_refs: ["receipt_workspace_change_control"],
        policy_decision_refs: ["policy_workspace_change_control"],
        evidence_refs: ["runtime_workspace_change_control_rust_owned"],
      };
    },
  };
  const store = fakeStore();

  const result = await controlWorkspaceChangeForThread(store, "thread_runtime", {
    workspace_change_id: "workspace_change:file:1",
    control_state: "accept",
    reason: "operator accepted",
    workspace_root: "/workspace/project",
    expected_head_ref: "head_before",
    state_root_ref: "state_after",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  }, { contextPolicyCore });

  assert.equal(captured.operation, "workspace_change_control");
  assert.equal(captured.operation_kind, "workspace_change.control");
  assert.equal(captured.thread_id, "thread_runtime");
  assert.equal(captured.event_stream_id, "thread_runtime:events");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.workspace_change_id, "workspace_change:file:1");
  assert.equal(captured.control_state, "accept");
  assert.equal(Object.hasOwn(captured, "workspace_change"), false);
  assert.deepEqual(captured.request.receipt_refs, ["receipt_request"]);
  assert.equal(captured.request.expected_head_ref, "head_before");
  assert.equal(captured.request.state_root_ref, "state_after");
  assert.deepEqual(captured.receipt_refs, ["receipt_request"]);
  assert.deepEqual(captured.evidence_refs, [
    "runtime_workspace_change_control_rust_owned",
    "runtime_workspace_change_control_event_rust_owned",
    "workspace_change_control_js_facade_retired",
    "agentgres_workspace_change_truth_required",
  ]);
  assert.deepEqual(store.calls, [
    { operation: "append_runtime_event", event: plannedEvent },
  ]);
  assert.deepEqual(result, { admitted: true, event: plannedEvent });
});

test("workspace change control fails closed before Rust planning or event append when planner is missing", async () => {
  const store = fakeStore();

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      workspace_change_id: "workspace_change:file:1",
      control_state: "accept",
    }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_change_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
      assert.equal(error.details.operation, "workspace_change_control");
      assert.equal(error.details.operation_kind, "workspace_change.control");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.equal(error.details.workspace_change_id, "workspace_change:file:1");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_workspace_change_control_rust_owned",
        "runtime_workspace_change_control_event_rust_owned",
        "workspace_change_control_js_facade_retired",
        "agentgres_workspace_change_truth_required",
      ]);
      assertNoRetiredWorkspaceChangeDetailAliases(error.details);
      return true;
    },
  );
  assert.deepEqual(store.calls, []);
});

test("workspace change control rejects retired per-family state_dir fallback before Rust planning", async () => {
  let planned = false;
  const contextPolicyCore = {
    planRuntimeWorkspaceChangeControl() {
      planned = true;
      assert.fail("workspace-change control must not use per-family state_dir fallback");
    },
  };
  const store = fakeStore({
    stateDir: null,
    workspaceChangeStateDir: "/retired-workspace-change-state",
  });

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      workspace_change_id: "workspace_change:file:1",
      control_state: "accept",
    }, { contextPolicyCore }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_workspace_change_daemon_state_dir_required");
      assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
      assert.equal(error.details.operation, "workspace_change_control");
      assert.equal(error.details.operation_kind, "workspace_change.control");
      assert.equal(error.details.thread_id, "thread_runtime");
      assert.equal(error.details.workspace_change_id, "workspace_change:file:1");
      assert.equal(
        error.details.evidence_refs.includes("runtime_workspace_change_family_state_dir_fallback_retired"),
        true,
      );
      assertNoRetiredWorkspaceChangeDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(planned, false);
  assert.deepEqual(store.calls, []);
});

test("workspace change control ignores retired request aliases before Rust planning", async () => {
  let planned = false;
  const contextPolicyCore = {
    planRuntimeWorkspaceChangeControl() {
      planned = true;
      assert.fail("retired workspace-change aliases must not reach Rust control planning");
    },
  };
  const store = fakeStore();

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      tool_id: "workspace_change__accept",
      toolId: "workspace_change__reject",
      input: {
        change_id: "workspace_change:file:0",
        changeId: "workspace_change:file:1",
        workspace_change_id: "workspace_change:file:2",
      },
      workspaceChangeId: "workspace_change:file:legacy",
      action: "accept",
      createdAt: "2026-06-12T00:00:00.000Z",
      requestHash: "retired_hash",
    }, { contextPolicyCore }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime_workspace_change_control_id_required");
      assert.equal(error.details.thread_id, "thread_runtime");
      assertNoRetiredWorkspaceChangeDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(planned, false);
  assert.deepEqual(store.calls, []);
});
