import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeApprovalSurface } from "./runtime-approval-surface.mjs";

function assertNoRetiredApprovalControlDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "approvalId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function createStore() {
  const store = {
    runtimeEventStreams: new Map(),
    agents: new Map(),
    runs: new Map(),
    agentForThread() {
      throw new Error("approval surface must not look up agents in JS");
    },
    appendRuntimeEvent() {
      throw new Error("approval surface must not append runtime events in JS");
    },
    writeAgent() {
      throw new Error("approval surface must not persist agents in JS");
    },
    writeRun() {
      throw new Error("approval surface must not persist runs in JS");
    },
  };
  const surface = createRuntimeApprovalSurface({
    approvalDecisionForRequest(value) {
      return value === "reject" || value === "rejected" ? "reject" : "approve";
    },
    runtimeError({ status, code, message, details }) {
      const error = new Error(message);
      error.status = status;
      error.code = code;
      error.details = details;
      return error;
    },
  });
  return { store, surface };
}

test("requestThreadApproval surface fails closed before agent lookup, event append, Rust planning, or JS persistence", () => {
  const { store, surface } = createStore();
  assert.throws(
    () => surface.requestThreadApproval(store, "thread_one", {
        approval_id: "approval_one",
        approvalId: "approval_retired",
        workflowGraphId: "graph_retired",
        workflowNodeId: "node_retired",
        idempotencyKey: "approval_request_idempotency_retired",
      }),
      (error) => {
        assert.equal(error.code, "runtime_approval_control_rust_core_required");
        assert.equal(error.status, 501);
        assert.equal(error.details.rust_core_boundary, "runtime.approval_control");
        assert.equal(error.details.operation, "approval_request");
        assert.equal(error.details.operation_kind, "approval.required");
        assert.equal(error.details.thread_id, "thread_one");
        assert.equal(error.details.approval_id, "approval_one");
        assert.deepEqual(error.details.evidence_refs, [
          "approval_request_js_facade_retired",
          "rust_daemon_core_approval_request_required",
          "agentgres_approval_request_state_truth_required",
        ]);
        assertNoRetiredApprovalControlDetailAliases(error.details);
        return true;
      },
    );

  assert.equal(store.runtimeEventStreams.size, 0);
  assert.equal(store.agents.size, 0);
  assert.equal(store.runs.size, 0);
});

test("approval decision readback facade is retired from the JS approval surface", () => {
  const { surface } = createStore();
  assert.equal(Object.hasOwn(surface, "latestApprovalDecisionEvent"), false);
  assert.equal(surface.latestApprovalDecisionEvent, undefined);
});

test("decideThreadApproval surface fails closed before lookup, event append, Rust planning, or JS persistence", () => {
  const { store, surface } = createStore();
  assert.throws(
    () => surface.decideThreadApproval(store, "thread_one", "approval_one", {
        decision: "approve",
        approvalId: "approval_retired",
        workflowGraphId: "graph_decision_retired",
        workflowNodeId: "node_decision_retired",
        idempotencyKey: "approval_decision_idempotency_retired",
      }),
      (error) => {
        assert.equal(error.code, "runtime_approval_control_rust_core_required");
        assert.equal(error.status, 501);
        assert.equal(error.details.rust_core_boundary, "runtime.approval_control");
        assert.equal(error.details.operation, "approval_decision");
        assert.equal(error.details.operation_kind, "approval.approve");
        assert.equal(error.details.thread_id, "thread_one");
        assert.equal(error.details.approval_id, "approval_one");
        assert.equal(error.details.decision, "approve");
        assert.deepEqual(error.details.evidence_refs, [
          "approval_decision_js_facade_retired",
          "rust_daemon_core_approval_decision_required",
          "agentgres_approval_decision_state_truth_required",
        ]);
        assertNoRetiredApprovalControlDetailAliases(error.details);
        return true;
      },
    );

  assert.equal(store.runtimeEventStreams.size, 0);
  assert.equal(store.agents.size, 0);
  assert.equal(store.runs.size, 0);
});

test("revokeThreadApproval surface fails closed before request lookup, event append, Rust planning, or JS persistence", () => {
  const { store, surface } = createStore();
  assert.throws(
    () => surface.revokeThreadApproval(store, "thread_one", "approval_one", {
        approvalId: "approval_retired",
        workflowGraphId: "graph_revoke_retired",
        workflowNodeId: "node_revoke_retired",
        idempotencyKey: "approval_revoke_idempotency_retired",
      }),
      (error) => {
        assert.equal(error.code, "runtime_approval_control_rust_core_required");
        assert.equal(error.status, 501);
        assert.equal(error.details.rust_core_boundary, "runtime.approval_control");
        assert.equal(error.details.operation, "approval_revoke");
        assert.equal(error.details.operation_kind, "approval.revoke");
        assert.equal(error.details.thread_id, "thread_one");
        assert.equal(error.details.approval_id, "approval_one");
        assert.deepEqual(error.details.evidence_refs, [
          "approval_revoke_js_facade_retired",
          "rust_daemon_core_approval_revoke_required",
          "agentgres_approval_revoke_state_truth_required",
        ]);
        assertNoRetiredApprovalControlDetailAliases(error.details);
        return true;
      },
    );

  assert.equal(store.runtimeEventStreams.size, 0);
  assert.equal(store.agents.size, 0);
  assert.equal(store.runs.size, 0);
});
