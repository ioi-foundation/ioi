import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeContextPolicySurface } from "./runtime-context-policy-surface.mjs";

function runtimeError(input) {
  const error = new Error(input.message);
  error.status = input.status;
  error.code = input.code;
  error.details = input.details;
  return error;
}

function assertNoRetiredContextPolicyDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "runId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function harness() {
  const calls = [];
  const events = [];
  const store = {
    appendRuntimeEvent(event) {
      events.push(event);
      throw new Error("Thread-bound context policy facade must not append JS runtime events.");
    },
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      throw new Error("Thread-bound context policy facade must not look up agents in JS.");
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      throw new Error("Thread-bound context policy facade must not look up runs in JS.");
    },
    listUsage(options) {
      calls.push({ name: "listUsage", options });
      return { total_tokens: 12, scope: "workflow" };
    },
    writeAgent() {
      throw new Error("Thread-bound context policy facade must not persist agent state in JS.");
    },
    writeRun() {
      throw new Error("Thread-bound context policy facade must not persist run state in JS.");
    },
  };
  const surface = createRuntimeContextPolicySurface({
    contextBudgetUsageTelemetryFromRequest(request) {
      calls.push({ name: "contextBudgetUsageTelemetryFromRequest", request });
      return request.usage_telemetry ?? null;
    },
    evaluateContextBudgetPolicy(input) {
      calls.push({ name: "evaluateContextBudgetPolicy", input });
      return {
        status: "passed",
        policy_decision_id: "policy_workflow_budget",
        receipt_refs: ["receipt_workflow_budget"],
        policy_decision_refs: ["policy_workflow_budget"],
        runtime_event_kind: "context_budget.evaluated",
        runtime_event_status: "completed",
      };
    },
    runtimeError,
  });
  return { calls, events, store, surface };
}

test("compactThread facade fails closed before event append, Rust planning, or JS persistence", () => {
  const { calls, events, store, surface } = harness();

  assert.throws(
    () => surface.compactThread(store, "thread_one", {
      turnId: "turn_retired",
      workflowGraphId: "graph_retired",
      idempotencyKey: "context_compaction_idempotency_retired",
    }),
    (error) => {
      assert.equal(error.code, "runtime_context_policy_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.context_policy");
      assert.equal(error.details.operation, "context_compaction");
      assert.equal(error.details.operation_kind, "thread.compact");
      assert.equal(error.details.thread_id, "thread_one");
      assert.deepEqual(error.details.evidence_refs, [
        "context_compaction_js_facade_retired",
        "rust_daemon_core_context_compaction_required",
        "agentgres_context_compaction_state_truth_required",
      ]);
      assertNoRetiredContextPolicyDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(events, []);
  assert.deepEqual(calls, []);
});

test("thread-bound context budget facade fails closed before event append or JS lookup", () => {
  const { calls, events, store, surface } = harness();

  assert.throws(
    () => surface.evaluateContextBudget(store, {
      threadId: "thread_one",
      request: {
        runId: "run_retired",
        workflowNodeId: "node_retired",
        idempotencyKey: "context_budget_idempotency_retired",
      },
    }),
    (error) => {
      assert.equal(error.code, "runtime_context_policy_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.context_policy");
      assert.equal(error.details.operation, "context_budget_evaluation");
      assert.equal(error.details.operation_kind, "context_budget.evaluate");
      assert.equal(error.details.thread_id, "thread_one");
      assert.equal(error.details.run_id, null);
      assert.deepEqual(error.details.evidence_refs, [
        "context_budget_evaluation_js_event_facade_retired",
        "rust_daemon_core_context_budget_event_required",
        "agentgres_context_budget_event_truth_required",
      ]);
      assertNoRetiredContextPolicyDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(events, []);
  assert.deepEqual(calls, []);
});

test("workflow-only context budget remains projection-only and ignores retired request aliases", () => {
  const { calls, events, store, surface } = harness();

  const result = surface.evaluateContextBudget(store, {
    request: {
      usage_telemetry: { total_tokens: 34 },
      eventKind: "RuntimeContextBudget.Retired",
      threadId: "thread_retired",
      runId: "run_retired",
      turnId: "turn_retired",
      workflowGraphId: "graph_retired",
      workflowNodeId: "node_retired",
    },
  });

  assert.equal(result.status, "passed");
  assert.deepEqual(events, []);
  const policyInput = calls.find((call) => call.name === "evaluateContextBudgetPolicy").input;
  assert.equal(policyInput.request.scope, "workflow");
  assert.equal(policyInput.request.thread_id, null);
  assert.equal(policyInput.request.run_id, null);
  assert.equal(policyInput.request.turn_id, null);
  for (const field of [
    "eventKind",
    "threadId",
    "runId",
    "turnId",
    "workflowGraphId",
    "workflowNodeId",
  ]) {
    assert.equal(Object.hasOwn(policyInput.request, field), false, `${field} alias must be absent`);
  }
});

test("compaction policy facade fails closed before event append, compaction execution, or JS persistence", () => {
  const { calls, events, store, surface } = harness();

  assert.throws(
    () => surface.evaluateCompactionPolicy(store, {
      threadId: "thread_one",
      request: {
        eventKind: "RuntimeCompactionPolicy.Retired",
        compactIdempotencyKey: "compaction_execute_idempotency_retired",
      },
    }),
    (error) => {
      assert.equal(error.code, "runtime_context_policy_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.context_policy");
      assert.equal(error.details.operation, "compaction_policy_evaluation");
      assert.equal(error.details.operation_kind, "compaction_policy.evaluate");
      assert.equal(error.details.thread_id, "thread_one");
      assert.deepEqual(error.details.evidence_refs, [
        "compaction_policy_evaluation_js_event_facade_retired",
        "rust_daemon_core_compaction_policy_event_required",
        "agentgres_compaction_policy_event_truth_required",
      ]);
      assertNoRetiredContextPolicyDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(events, []);
  assert.deepEqual(calls, []);
});

test("compaction policy still rejects missing thread id as a request error", () => {
  const { store, surface } = harness();

  assert.throws(
    () => surface.evaluateCompactionPolicy(store, { request: {} }),
    (error) => {
      assert.equal(error.code, "runtime_compaction_policy_thread_required");
      assert.equal(error.status, 400);
      return true;
    },
  );
});
