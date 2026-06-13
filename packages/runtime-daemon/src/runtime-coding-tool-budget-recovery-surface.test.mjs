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

test("coding-tool budget recovery control fails closed before JS approval, event append, or run persistence without Rust planner", () => {
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
        "coding_tool_budget_recovery_state_update_rust_owned",
        "rust_daemon_core_budget_recovery_state_update",
        "rust_agentgres_runtime_run_state_commit",
      ]);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("coding-tool budget recovery retry completion uses Rust planner and Agentgres run commit", () => {
  const calls = [];
  const run = { id: "run_alpha", agentId: "agent_alpha", trace: {} };
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return run;
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      throw new Error("Budget recovery facade must not append JS runtime events.");
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        commit_hash: "sha256:commit",
        receipt_refs: ["receipt_commit"],
        policy_decision_refs: ["policy_commit"],
      };
    },
  };
  const runnerCalls = [];
  const surface = createRuntimeCodingToolBudgetRecoverySurface({
    runtimeError,
    codingToolBudgetRecoveryRunner: {
      planCodingToolBudgetRecoveryStateUpdate(request) {
        runnerCalls.push(request);
        return {
          source: "rust_coding_tool_budget_recovery_state_update_command",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "workflow.run.retry_completed",
          operator_control: {
            control: "coding_tool_budget_recovery",
            action: "retry_approved",
            approval_id: request.approval_id,
            event_id: request.event_id,
            seq: request.seq,
            receipt_refs: request.receipt_refs,
            policy_decision_refs: request.policy_decision_refs,
            created_at: request.created_at,
          },
          run: {
            ...request.run,
            updatedAt: request.created_at,
            trace: {
              operatorControls: [{
                control: "coding_tool_budget_recovery",
                action: "retry_approved",
                approval_id: request.approval_id,
                event_id: request.event_id,
              }],
            },
          },
        };
      },
    },
  });

  const result = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    thread_id: "thread_alpha",
    action: "retry-approved",
    approval_id: "approval_alpha",
    source_event_id: "event_budget",
    event_id: "event_retry",
    seq: 12,
    created_at: "2026-06-12T10:30:00.000Z",
    source: "agent_studio",
    receipt_refs: ["receipt_retry"],
    policy_decision_refs: ["policy_retry"],
  });

  assert.deepEqual(runnerCalls, [{
    thread_id: "thread_alpha",
    run_id: "run_alpha",
    run,
    event_id: "event_retry",
    seq: 12,
    created_at: "2026-06-12T10:30:00.000Z",
    approval_id: "approval_alpha",
    source: "agent_studio",
    receipt_refs: ["receipt_retry"],
    policy_decision_refs: ["policy_retry"],
  }]);
  assert.equal(result.status, "completed");
  assert.equal(result.operation_kind, "workflow.run.retry_completed");
  assert.equal(result.action, "retry_approved");
  assert.equal(result.run_id, "run_alpha");
  assert.equal(result.operator_control.approval_id, "approval_alpha");
  assert.deepEqual(result.receipt_refs, ["receipt_retry", "receipt_commit"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_retry", "policy_commit"]);
  assert.deepEqual(result.evidence_refs, [
    "coding_tool_budget_recovery_state_update_rust_owned",
    "rust_daemon_core_budget_recovery_state_update",
    "rust_agentgres_runtime_run_state_commit",
  ]);
  assert.deepEqual(calls, [
    { name: "getRun", runId: "run_alpha" },
    { name: "writeRun", run: result.run, operationKind: "workflow.run.retry_completed" },
  ]);
  for (const alias of [
    "threadId",
    "runId",
    "approvalId",
    "sourceEventId",
    "receiptRefs",
    "policyDecisionRefs",
  ]) {
    assert.equal(Object.hasOwn(result, alias), false, `${alias} output alias must be absent`);
    assert.equal(Object.hasOwn(result.operator_control, alias), false, `${alias} operator alias must be absent`);
  }
});

test("coding-tool budget recovery request approval uses Rust control planner and Agentgres run commit", () => {
  const calls = [];
  const runnerCalls = [];
  const run = { id: "run_alpha", agentId: "agent_alpha", status: "running", trace: {} };
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return run;
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        receipt_refs: ["receipt_commit"],
        policy_decision_refs: ["policy_commit"],
      };
    },
  };
  const surface = createRuntimeCodingToolBudgetRecoverySurface({
    runtimeError,
    codingToolBudgetRecoveryRunner: {
      planCodingToolBudgetRecoveryControl(request) {
        runnerCalls.push(request);
        return {
          source: "rust_coding_tool_budget_recovery_control_command",
          backend: "rust_policy",
          status: "planned",
          action: "request_approval",
          operation_kind: "workflow.run.coding_tool_budget_recovery.request_approval",
          operator_control: {
            control: "coding_tool_budget_recovery",
            action: "request_approval",
            approval_id: request.approval_id,
            status: "waiting_for_approval",
            event_id: request.event_id,
            seq: request.seq,
            receipt_refs: request.receipt_refs,
            policy_decision_refs: request.policy_decision_refs,
            created_at: request.created_at,
          },
          run: {
            ...request.run,
            updatedAt: request.created_at,
            status: "blocked",
            turnStatus: "waiting_for_approval",
          },
        };
      },
    },
  });

  const result = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    thread_id: "thread_alpha",
    action: "request_approval",
    approval_id: "approval_alpha",
    source_event_id: "event_budget",
    event_id: "event_budget_request",
    seq: 21,
    created_at: "2026-06-12T10:35:00.000Z",
    source: "agent_studio",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  });

  assert.deepEqual(runnerCalls, [{
    operation: "coding_tool_budget_recovery_control",
    operation_kind: "workflow.run.coding_tool_budget_recovery",
    run_id: "run_alpha",
    thread_id: "thread_alpha",
    action: "request_approval",
    approval_id: "approval_alpha",
    source_event_id: "event_budget",
    source: "agent_studio",
    run,
    event_id: "event_budget_request",
    seq: 21,
    created_at: "2026-06-12T10:35:00.000Z",
    reason: null,
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
    authority_grant_refs: [],
    authority_receipt_refs: [],
    authority_context: {},
    evidence_refs: [
      "coding_tool_budget_recovery_control_rust_owned",
      "rust_daemon_core_budget_recovery_control",
      "rust_agentgres_runtime_run_state_commit",
    ],
  }]);
  assert.equal(result.status, "waiting_for_approval");
  assert.equal(result.operation_kind, "workflow.run.coding_tool_budget_recovery.request_approval");
  assert.equal(result.action, "request_approval");
  assert.deepEqual(result.receipt_refs, ["receipt_request", "receipt_commit"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_request", "policy_commit"]);
  assert.deepEqual(result.evidence_refs, [
    "coding_tool_budget_recovery_control_rust_owned",
    "rust_daemon_core_budget_recovery_control",
    "rust_agentgres_runtime_run_state_commit",
  ]);
  assert.deepEqual(calls, [
    { name: "getRun", runId: "run_alpha" },
    {
      name: "writeRun",
      run: result.run,
      operationKind: "workflow.run.coding_tool_budget_recovery.request_approval",
    },
  ]);
  assert.equal(Object.hasOwn(result, "approvalId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "approvalId"), false);
});

test("coding-tool budget recovery approve override uses Rust wallet authority control", () => {
  const calls = [];
  const runnerCalls = [];
  const run = { id: "run_alpha", agentId: "agent_alpha", trace: {} };
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return run;
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      return { receipt_refs: ["receipt_commit"], policy_decision_refs: ["policy_commit"] };
    },
  };
  const surface = createRuntimeCodingToolBudgetRecoverySurface({
    runtimeError,
    codingToolBudgetRecoveryRunner: {
      planCodingToolBudgetRecoveryControl(request) {
        runnerCalls.push(request);
        return {
          source: "rust_coding_tool_budget_recovery_control_command",
          backend: "rust_policy",
          status: "planned",
          action: "approve_override",
          operation_kind: "workflow.run.coding_tool_budget_recovery.approve_override",
          wallet_network_grant_refs: request.authority_grant_refs,
          authority_receipt_refs: request.authority_receipt_refs,
          authority_hash: "sha256:budget-authority",
          operator_control: {
            control: "coding_tool_budget_recovery",
            action: "approve_override",
            approval_id: request.approval_id,
            status: "override_approved",
            event_id: request.event_id,
            seq: request.seq,
            receipt_refs: request.receipt_refs,
            policy_decision_refs: request.policy_decision_refs,
            wallet_network_grant_refs: request.authority_grant_refs,
            authority_receipt_refs: request.authority_receipt_refs,
            authority_hash: "sha256:budget-authority",
            direct_truth_write_allowed: false,
          },
          run: { ...request.run, updatedAt: request.created_at },
        };
      },
    },
  });

  const result = surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
    thread_id: "thread_alpha",
    action: "approve_override",
    approval_id: "approval_alpha",
    source_event_id: "event_budget",
    event_id: "event_budget_override",
    seq: 22,
    created_at: "2026-06-12T10:36:00.000Z",
    authority_grant_refs: ["wallet.network://grant/coding-tool-budget-recovery"],
    authority_receipt_refs: ["receipt://wallet.network/coding-tool-budget-recovery"],
    policy_decision_refs: ["policy_override"],
  });

  assert.deepEqual(runnerCalls[0].authority_grant_refs, [
    "wallet.network://grant/coding-tool-budget-recovery",
  ]);
  assert.deepEqual(runnerCalls[0].authority_receipt_refs, [
    "receipt://wallet.network/coding-tool-budget-recovery",
  ]);
  assert.equal(result.status, "override_approved");
  assert.equal(result.operation_kind, "workflow.run.coding_tool_budget_recovery.approve_override");
  assert.deepEqual(result.wallet_network_grant_refs, [
    "wallet.network://grant/coding-tool-budget-recovery",
  ]);
  assert.deepEqual(result.authority_receipt_refs, [
    "receipt://wallet.network/coding-tool-budget-recovery",
  ]);
  assert.equal(result.authority_hash, "sha256:budget-authority");
  assert.equal(result.operator_control.direct_truth_write_allowed, false);
  assert.deepEqual(calls, [
    { name: "getRun", runId: "run_alpha" },
    {
      name: "writeRun",
      run: result.run,
      operationKind: "workflow.run.coding_tool_budget_recovery.approve_override",
    },
  ]);
});

test("coding-tool budget blocked-event projection facade is retired", () => {
  const { calls, surface } = harness();
  assert.equal(Object.hasOwn(surface, "latestCodingToolBudgetBlockedEventForRun"), false);
  assert.equal(surface.latestCodingToolBudgetBlockedEventForRun, undefined);
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

test("coding-tool budget recovery request approval fails before JS lookup when canonical control inputs are missing", () => {
  const calls = [];
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("Budget recovery facade must not look up runs before canonical control inputs are present.");
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      throw new Error("Budget recovery facade must not persist before canonical control inputs are present.");
    },
  };
  const surface = createRuntimeCodingToolBudgetRecoverySurface({
    runtimeError,
    codingToolBudgetRecoveryRunner: {
      planCodingToolBudgetRecoveryControl() {
        throw new Error("Rust control planner must not run before required canonical inputs are present.");
      },
    },
  });

  assert.throws(
    () =>
      surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
        thread_id: "thread_alpha",
        action: "request_approval",
        approval_id: "approval_alpha",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime_coding_tool_budget_recovery_control_input_required");
      assert.equal(error.details.run_id, "run_alpha");
      assert.equal(error.details.event_id, null);
      assert.equal(error.details.seq, null);
      assert.equal(error.details.created_at, null);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("coding-tool budget recovery retry completion fails before JS lookup when canonical state-update inputs are missing", () => {
  const calls = [];
  const store = {
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("Budget recovery facade must not look up runs before canonical state inputs are present.");
    },
    writeRun(run, operationKind) {
      calls.push({ name: "writeRun", run, operationKind });
      throw new Error("Budget recovery facade must not persist before canonical state inputs are present.");
    },
  };
  const surface = createRuntimeCodingToolBudgetRecoverySurface({
    runtimeError,
    codingToolBudgetRecoveryRunner: {
      planCodingToolBudgetRecoveryStateUpdate() {
        throw new Error("Rust planner must not run before required canonical inputs are present.");
      },
    },
  });

  assert.throws(
    () =>
      surface.codingToolBudgetRecoveryForRun(store, "run_alpha", {
        thread_id: "thread_alpha",
        action: "retry_approved",
        approval_id: "approval_alpha",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime_coding_tool_budget_recovery_state_update_input_required");
      assert.equal(error.details.run_id, "run_alpha");
      assert.equal(error.details.event_id, null);
      assert.equal(error.details.seq, null);
      assert.equal(error.details.created_at, null);
      assertNoRetiredBudgetRecoveryDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(calls, []);
});
