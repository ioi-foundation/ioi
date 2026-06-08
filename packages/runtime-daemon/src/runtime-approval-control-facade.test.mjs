import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

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
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-approval-control-facade-"));
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    approvalStateRunner: {
      planApprovalRequestStateUpdate() {
        throw new Error("JS approval request facade must not invoke the Rust planner bridge.");
      },
      planApprovalDecisionStateUpdate() {
        throw new Error("JS approval decision facade must not invoke the Rust planner bridge.");
      },
      planApprovalRevokeStateUpdate() {
        throw new Error("JS approval revoke facade must not invoke the Rust planner bridge.");
      },
    },
  });
  return { stateDir, store };
}

test("requestThreadApproval facade fails closed before agent lookup, event append, Rust planning, or JS persistence", () => {
  const { stateDir, store } = createStore();
  try {
    assert.throws(
      () => store.requestThreadApproval("thread_one", {
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
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("decideThreadApproval facade fails closed before lookup, event append, Rust planning, or JS persistence", () => {
  const { stateDir, store } = createStore();
  try {
    assert.throws(
      () => store.decideThreadApproval("thread_one", "approval_one", {
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
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("revokeThreadApproval facade fails closed before request lookup, event append, Rust planning, or JS persistence", () => {
  const { stateDir, store } = createStore();
  try {
    assert.throws(
      () => store.revokeThreadApproval("thread_one", "approval_one", {
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
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
