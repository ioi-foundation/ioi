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

function compactHarness() {
  const calls = [];
  const events = [];
  const agent = {
    id: "agent_one",
    status: "active",
    cwd: "/workspace",
    updatedAt: "2026-06-13T12:00:00.000Z",
  };
  const run = {
    id: "run_one",
    agentId: "agent_one",
    status: "running",
    updatedAt: "2026-06-13T12:00:00.000Z",
    trace: {},
  };
  const runner = {
    planContextCompaction(request) {
      calls.push({ name: "planContextCompaction", request });
      return {
        backend: "rust_policy",
        status: "planned",
        thread_id: request.thread_id,
        agent_id: request.agent_id,
        run_id: request.run_id,
        turn_id: request.turn_id,
        event_stream_id: request.event_stream_id,
        item_id: `${request.thread_id}:item:context-compact:hash_one`,
        idempotency_key: `thread:${request.thread_id}:context.compact:hash_one`,
        source: request.source,
        source_event_kind: "OperatorControl.Compact",
        event_kind: "context.compacted",
        actor: request.actor,
        requested_by: request.requested_by,
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        component_kind: "context_compaction",
        payload_schema_version: "ioi.runtime.context-compaction.v1",
        payload: {
          reason: request.reason,
          scope: request.scope,
          previous_latest_seq: request.previous_latest_seq,
        },
        receipt_refs: ["receipt_context_compaction_plan"],
        policy_decision_refs: ["policy_context_compaction_plan"],
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        reason: request.reason,
        scope: request.scope,
        previous_latest_seq: request.previous_latest_seq,
      };
    },
    planContextCompactionStateUpdate(request) {
      calls.push({ name: "planContextCompactionStateUpdate", request });
      const operatorControl = {
        control: "compact",
        source: request.source,
        reason: request.reason,
        scope: request.scope,
        event_id: request.event_id,
        seq: request.seq,
        created_at: request.created_at,
      };
      const contextCompaction = {
        reason: request.reason,
        scope: request.scope,
        event_id: request.event_id,
        seq: request.seq,
        compacted_tokens: 0,
      };
      return {
        source: "rust_context_compaction_state_update_command",
        backend: "rust_policy",
        status: "planned",
        target_kind: request.target_kind,
        operation_kind: "thread.compact",
        updated_at: request.created_at,
        operator_control: operatorControl,
        context_compaction: contextCompaction,
        run: request.target_kind === "run"
          ? {
              ...request.run,
              updatedAt: request.created_at,
              trace: {
                ...(request.run.trace ?? {}),
                contextCompaction,
                operatorControls: [operatorControl],
              },
            }
          : null,
        agent: request.target_kind === "agent"
          ? {
              ...request.agent,
              updatedAt: request.created_at,
            }
          : null,
      };
    },
  };
  const store = {
    contextPolicyRunner: runner,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return agent;
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return runId === run.id ? run : null;
    },
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ name: "latestRuntimeEventSeq", eventStreamId });
      return 4;
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      const admitted = {
        ...event,
        admitted: true,
        receipt_refs: [...event.receipt_refs, "receipt_context_compaction_admitted"],
      };
      events.push(admitted);
      return admitted;
    },
    writeRun(plannedRun, operationKind) {
      calls.push({ name: "writeRun", plannedRun, operationKind });
      return {
        operation_kind: operationKind,
        receipt_refs: [`receipt://${operationKind}/${plannedRun.id}`],
        policy_decision_refs: [`policy://${operationKind}/${plannedRun.id}`],
      };
    },
    writeAgent(plannedAgent, operationKind) {
      calls.push({ name: "writeAgent", plannedAgent, operationKind });
      return {
        operation_kind: operationKind,
        receipt_refs: [`receipt://${operationKind}/${plannedAgent.id}`],
        policy_decision_refs: [`policy://${operationKind}/${plannedAgent.id}`],
      };
    },
  };
  const surface = createRuntimeContextPolicySurface({
    eventStreamIdForThread: (threadId) => `event_stream_${threadId}`,
    runtimeError,
  });
  return { calls, events, store, surface };
}

test("compactThread uses Rust compaction planning, event admission, and run persistence", () => {
  const { calls, events, store, surface } = compactHarness();

  const result = surface.compactThread(store, "thread_one", {
    run_id: "run_one",
    turn_id: "turn_one",
    reason: "trim context",
    scope: "run",
    source: "sdk_client",
    created_at: "2026-06-13T12:05:00.000Z",
    workflow_graph_id: "graph_one",
    workflow_node_id: "node_one",
    turnId: "turn_retired",
    workflowGraphId: "graph_retired",
    idempotencyKey: "context_compaction_idempotency_retired",
  });

  assert.equal(result.status, "completed");
  assert.equal(result.operation, "context_compaction");
  assert.equal(result.operation_kind, "thread.compact");
  assert.equal(result.target_kind, "run");
  assert.equal(result.event.admitted, true);
  assert.equal(result.event.event_kind, "context.compacted");
  assert.equal(result.event.event_id, "event_context_compaction_thread_one_run_one_00000005");
  assert.equal(result.operator_control.event_id, result.event.event_id);
  assert.equal(result.context_compaction.compacted_tokens, 0);
  assert.equal(result.run.trace.contextCompaction.event_id, result.event.event_id);
  assert.equal(result.receipt_refs.includes("receipt_context_compaction_admitted"), true);
  assert.equal(result.receipt_refs.includes("receipt://thread.compact/run_one"), true);
  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "getRun",
    "latestRuntimeEventSeq",
    "planContextCompaction",
    "appendRuntimeEvent",
    "planContextCompactionStateUpdate",
    "writeRun",
  ]);
  assert.equal(calls[3].request.thread_id, "thread_one");
  assert.equal(calls[3].request.run_id, "run_one");
  assert.equal(calls[3].request.turn_id, "turn_one");
  assert.equal(calls[3].request.previous_latest_seq, 4);
  assert.equal(calls[5].request.event_id, result.event.event_id);
  assert.equal(calls[5].request.target_kind, "run");
  assert.equal(events.length, 1);
  for (const key of ["turnId", "workflowGraphId", "idempotencyKey"]) {
    assert.equal(Object.hasOwn(calls[3].request, key), false, `${key} alias must be absent`);
  }
});

test("compactThread uses Rust runless agent update when no run is targeted", () => {
  const { calls, store, surface } = compactHarness();

  const result = surface.compactThread(store, "thread_one", {
    reason: "trim thread context",
    target_kind: "agent",
    created_at: "2026-06-13T12:06:00.000Z",
  });

  assert.equal(result.status, "completed");
  assert.equal(result.target_kind, "agent");
  assert.equal(result.run, null);
  assert.equal(result.agent.id, "agent_one");
  assert.equal(result.event.event_id, "event_context_compaction_thread_one_agent_one_00000005");
  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "latestRuntimeEventSeq",
    "planContextCompaction",
    "appendRuntimeEvent",
    "planContextCompactionStateUpdate",
    "writeAgent",
  ]);
  assert.equal(calls[4].request.target_kind, "agent");
  assert.equal(calls[5].operationKind, "thread.compact");
});

test("compactThread fails closed when targeted run has no admitted record", () => {
  const { calls, events, store, surface } = compactHarness();
  store.getRun = (runId) => {
    calls.push({ name: "getRun", runId });
    return null;
  };

  assert.throws(
    () => surface.compactThread(store, "thread_one", {
      run_id: "run_missing",
      turn_id: "turn_one",
      created_at: "2026-06-13T12:07:00.000Z",
    }),
    (error) => {
      assert.equal(error.code, "runtime_context_compaction_run_unavailable");
      assert.equal(error.status, 404);
      assert.equal(error.details.rust_core_boundary, "runtime.context_policy");
      assert.equal(error.details.thread_id, "thread_one");
      assert.equal(error.details.run_id, "run_missing");
      assert.equal(error.details.turn_id, "turn_one");
      return true;
    },
  );

  assert.deepEqual(calls.map((call) => call.name), ["agentForThread", "getRun"]);
  assert.deepEqual(events, []);
});

test("compactThread fails closed when Rust event admission omits admitted identity", () => {
  const { calls, store, surface } = compactHarness();
  store.appendRuntimeEvent = (event) => {
    calls.push({ name: "appendRuntimeEvent", event });
    return null;
  };

  assert.throws(
    () => surface.compactThread(store, "thread_one", {
      run_id: "run_one",
      turn_id: "turn_one",
      created_at: "2026-06-13T12:08:00.000Z",
    }),
    (error) => {
      assert.equal(error.code, "runtime_context_compaction_event_admission_incomplete");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.context_policy");
      assert.equal(error.details.thread_id, "thread_one");
      assert.equal(error.details.run_id, "run_one");
      assert.equal(error.details.event_id, "event_context_compaction_thread_one_run_one_00000005");
      assert.equal(error.details.seq, 5);
      return true;
    },
  );

  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "getRun",
    "latestRuntimeEventSeq",
    "planContextCompaction",
    "appendRuntimeEvent",
  ]);
});

test("compactThread fails closed before lookup or event append without Rust planning", () => {
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
