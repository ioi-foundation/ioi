import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolBudgetRecoverySurface } from "./runtime-coding-tool-budget-recovery-surface.mjs";

function runtimeError(input) {
  const error = new Error(input.message);
  error.status = input.status;
  error.code = input.code;
  error.details = input.details;
  return error;
}

function assertNoRetiredBudgetRecoveryDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "runId",
    "approvalId",
    "sourceEventId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function harness() {
  const calls = [];
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("Budget recovery facade must not look up runs in JS.");
    },
    getAgent(agentId) {
      calls.push({ name: "getAgent", agentId });
      throw new Error("Budget recovery facade must not look up agents in JS.");
    },
    projectThreadEvents(agent) {
      calls.push({ name: "projectThreadEvents", agent });
      throw new Error("Budget recovery facade must not project accepted truth in JS.");
    },
    requestThreadApproval(threadId, request) {
      calls.push({ name: "requestThreadApproval", threadId, request });
      throw new Error("Budget recovery facade must not request approval through JS.");
    },
    decideThreadApproval(threadId, approvalId, request) {
      calls.push({ name: "decideThreadApproval", threadId, approvalId, request });
      throw new Error("Budget recovery facade must not decide approval through JS.");
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      throw new Error("Budget recovery facade must not append JS runtime events.");
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      throw new Error("Budget recovery facade must not persist run state in JS.");
    },
    runs: {
      set(runId, run) {
        calls.push({ name: "runs.set", runId, run });
        throw new Error("Budget recovery facade must not mutate run maps in JS.");
      },
    },
  };
  const surface = createRuntimeCodingToolBudgetRecoverySurface({ runtimeError });
  return { calls, store, surface };
}

test("coding-tool budget recovery control facade fails closed before JS approval, event append, planner, or run persistence", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
        threadId: "thread_retired",
        thread_id: "thread_alpha",
        recoveryAction: "retry_retired",
        recovery_action: "retry_approved",
        approvalId: "approval_retired",
        approval_id: "approval_alpha",
        sourceEventId: "event_retired",
        source_event_id: "event_budget",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_budget_recovery_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_budget_recovery");
      assert.equal(error.details.operation, "coding_tool_budget_recovery_control");
      assert.equal(error.details.operation_kind, "workflow.run.coding_tool_budget_recovery");
      assert.equal(error.details.run_id, "run_alpha");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.action, "retry_approved");
      assert.equal(error.details.approval_id, "approval_alpha");
      assert.equal(error.details.source_event_id, "event_budget");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_budget_recovery_js_facade_retired",
        "rust_daemon_core_budget_recovery_admission_required",
        "agentgres_budget_recovery_state_truth_required",
      ]);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("coding-tool budget blocked-event projection facade fails closed before JS projection reads", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.latestCodingToolBudgetBlockedEventForRun(store, "run_alpha", "event_budget"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_budget_recovery_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_budget_recovery");
      assert.equal(error.details.operation, "coding_tool_budget_blocked_event_projection");
      assert.equal(error.details.operation_kind, "workflow.run.coding_tool_budget_blocked.project");
      assert.equal(error.details.run_id, "run_alpha");
      assert.equal(error.details.source_event_id, "event_budget");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_budget_blocked_event_js_projection_retired",
        "rust_daemon_core_coding_tool_budget_recovery_projection_required",
        "agentgres_coding_tool_budget_recovery_projection_truth_required",
      ]);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("coding-tool budget recovery defaults action canonically while ignoring retired aliases", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () =>
      surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
        recoveryAction: "approve_override",
        approvalId: "approval_retired",
        sourceEventId: "event_retired",
      }),
    (error) => {
      assert.equal(error.details.action, "request_approval");
      assert.equal(error.details.approval_id, null);
      assert.equal(error.details.source_event_id, null);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});
