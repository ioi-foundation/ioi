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

function failIfCalled(name) {
  return () => {
    throw new Error(`${name} must not be called`);
  };
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

function harness({ contextPolicyCore = null } = {}) {
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
    contextPolicyCore,
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
    evaluateContextBudgetPolicy(request) {
      calls.push({ name: "evaluateContextBudgetPolicy", request });
      const status = request.mode === "block" ? "blocked" : "ok";
      return {
        schema_version: "ioi.runtime.context-budget-policy.v1",
        object: "ioi.runtime_context_budget_policy",
        source: "rust_context_budget_policy_command",
        backend: "rust_policy",
        status,
        mode: request.mode,
        scope: request.scope,
        thread_id: request.thread_id,
        turn_id: request.turn_id,
        run_id: request.run_id,
        actor: request.actor,
        event_kind: request.event_kind,
        component_kind: "context_budget",
        payload_schema_version: "ioi.runtime.context-budget-policy.v1",
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        thresholds: request.thresholds,
        usage_telemetry: request.usage_telemetry,
        usage_summary: { total_tokens: request.usage_telemetry.total_tokens ?? 0 },
        policy_decision_id: "policy_context_budget_thread_mock",
        policy_decision: { status },
        receipt_refs: ["receipt_context_budget_thread_mock"],
        policy_decision_refs: ["policy_context_budget_thread_mock"],
        warnings: [],
        violations: status === "blocked" ? [{ id: "total_tokens" }] : [],
        would_block: status === "blocked",
        runtime_event_kind: status === "blocked" ? "policy.blocked" : "context_budget.evaluated",
        runtime_event_status: status === "blocked" ? "blocked" : "completed",
        runtime_event_item_id:
          `${request.turn_id ?? request.thread_id}:item:context-budget:policy_context_budget_thread_mock`,
        runtime_event_idempotency_key:
          `thread:${request.thread_id}:context-budget:policy_context_budget_thread_mock`,
        summary:
          status === "blocked"
            ? "Context budget blocked: total tokens exceeded."
            : "Context budget is within policy.",
      };
    },
    evaluateCompactionPolicy(request) {
      calls.push({ name: "evaluateCompactionPolicy", request });
      const approvalGranted = request.approval?.approval_granted === true;
      const executeCompaction = request.compact?.execute_compaction === true;
      const action = approvalGranted && executeCompaction ? "compact" : "approval_required";
      const status = action === "compact" ? "compacted" : "waiting";
      return {
        schema_version: "ioi.runtime.compaction-policy.v1",
        object: "ioi.runtime_compaction_policy",
        source: "rust_compaction_policy_command",
        backend: "rust_policy",
        status,
        action,
        selected_action: "compact",
        budget_status: "blocked",
        thread_id: request.thread_id,
        turn_id: request.turn_id,
        actor: request.actor,
        event_kind: request.event_kind,
        component_kind: "compaction_policy",
        payload_schema_version: "ioi.runtime.compaction-policy.v1",
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        policy_decision_id: "policy_compaction_thread_mock",
        receipt_refs: ["receipt_compaction_policy_thread_mock"],
        policy_decision_refs: ["policy_compaction_thread_mock"],
        approval_id: action === "approval_required" ? "approval_compaction_thread_mock" : null,
        approval_required: true,
        approval_granted: approvalGranted,
        approval_satisfied: approvalGranted,
        execute_compaction: executeCompaction,
        compaction_requested: action === "compact",
        compaction_executed: false,
        compaction_event_id: null,
        compaction_seq: null,
        compact_reason: request.compact?.compact_reason ?? "trim context after budget block",
        compact_scope: request.compact?.compact_scope ?? "thread",
        compact_idempotency_key:
          "thread:thread_one:compaction-policy:compact:policy_compaction_thread_mock",
        compact_workflow_node_id:
          request.compact?.compact_workflow_node_id ?? "runtime.context-compact",
        continuation_allowed: true,
        runtime_event_kind:
          action === "approval_required" ? "approval.required" : "compaction_policy.evaluated",
        runtime_event_status: action === "approval_required" ? "waiting" : "completed",
        runtime_event_item_id:
          `${request.turn_id ?? request.thread_id}:item:compaction-policy:policy_compaction_thread_mock`,
        runtime_event_idempotency_key:
          `thread:${request.thread_id}:compaction-policy:policy_compaction_thread_mock`,
        context_budget: request.context_budget,
        summary:
          action === "approval_required"
            ? "Compaction policy requires operator approval before compacting."
            : "Compaction policy executed context compaction.",
      };
    },
    planContextCompaction(request) {
      calls.push({ name: "planContextCompaction", request });
      assert.equal(request.state_dir, "/runtime-state");
      assert.equal(Object.hasOwn(request, "previous_latest_seq"), false);
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
          previous_latest_seq: 4,
        },
        receipt_refs: ["receipt_context_compaction_plan"],
        policy_decision_refs: ["policy_context_compaction_plan"],
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        reason: request.reason,
        scope: request.scope,
        previous_latest_seq: 4,
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
    stateDir: "/runtime-state",
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return agent;
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return runId === run.id ? run : null;
    },
    latestRuntimeEventSeq: failIfCalled("latestRuntimeEventSeq"),
    usageForThread(threadId) {
      calls.push({ name: "usageForThread", threadId });
      return { total_tokens: 120, thread_id: threadId, scope: "thread" };
    },
    usageForRun(runId) {
      calls.push({ name: "usageForRun", runId });
      return { total_tokens: 80, thread_id: "thread_one", run_id: runId, turn_id: "turn_one", scope: "run" };
    },
    appendRuntimeEvent(event) {
      calls.push({ name: "appendRuntimeEvent", event });
      const seq = events.length + 5;
      const admitted = {
        ...event,
        seq: event.seq ?? seq,
        admitted: true,
        receipt_refs: [...event.receipt_refs, `receipt_${event.component_kind}_admitted`],
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
    contextPolicyCore: runner,
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
  assert.equal(result.event.event_id, "event_context_compaction_thread_one_run_one_2026-06-13T12:05:00.000Z");
  assert.equal(result.operator_control.event_id, result.event.event_id);
  assert.equal(result.context_compaction.compacted_tokens, 0);
  assert.equal(result.run.trace.contextCompaction.event_id, result.event.event_id);
  assert.equal(result.receipt_refs.includes("receipt_context_compaction_admitted"), true);
  assert.equal(result.receipt_refs.includes("receipt://thread.compact/run_one"), true);
  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "getRun",
    "planContextCompaction",
    "appendRuntimeEvent",
    "planContextCompactionStateUpdate",
    "writeRun",
  ]);
  assert.equal(calls[2].request.thread_id, "thread_one");
  assert.equal(calls[2].request.run_id, "run_one");
  assert.equal(calls[2].request.turn_id, "turn_one");
  assert.equal(calls[2].request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[2].request, "previous_latest_seq"), false);
  assert.equal(calls[4].request.event_id, result.event.event_id);
  assert.equal(calls[4].request.target_kind, "run");
  assert.equal(events.length, 1);
  for (const key of ["turnId", "workflowGraphId", "idempotencyKey"]) {
    assert.equal(Object.hasOwn(calls[2].request, key), false, `${key} alias must be absent`);
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
  assert.equal(result.event.event_id, "event_context_compaction_thread_one_agent_one_2026-06-13T12:06:00.000Z");
  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "planContextCompaction",
    "appendRuntimeEvent",
    "planContextCompactionStateUpdate",
    "writeAgent",
  ]);
  assert.equal(calls[3].request.target_kind, "agent");
  assert.equal(calls[4].operationKind, "thread.compact");
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
      assert.equal(error.details.event_id, "event_context_compaction_thread_one_run_one_2026-06-13T12:08:00.000Z");
      assert.equal(Object.hasOwn(error.details, "seq"), false);
      return true;
    },
  );

  assert.deepEqual(calls.map((call) => call.name), [
    "agentForThread",
    "getRun",
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

test("thread-bound context budget uses Rust policy planning and event admission", () => {
  const { calls, events, store, surface } = compactHarness();

  const result = surface.evaluateContextBudget(store, {
    threadId: "thread_one",
    request: {
      mode: "block",
      thresholds: { max_total_tokens: 100 },
      created_at: "2026-06-13T12:09:00.000Z",
      workflow_graph_id: "graph_one",
      workflow_node_id: "node_budget",
      runId: "run_retired",
      workflowNodeId: "node_retired",
      idempotencyKey: "context_budget_idempotency_retired",
    },
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.event.admitted, true);
  assert.equal(result.event.event_kind, "policy.blocked");
  assert.equal(result.event.event_id, "event_context_budget_thread_one_policy_context_budget_thread_mock_2026-06-13T12:09:00.000Z");
  assert.equal(result.event.payload.policy_decision_id, "policy_context_budget_thread_mock");
  assert.equal(result.receipt_refs.includes("receipt_context_budget_admitted"), true);
  assert.deepEqual(calls.map((call) => call.name), [
    "usageForThread",
    "evaluateContextBudgetPolicy",
    "appendRuntimeEvent",
  ]);
  assert.equal(calls[1].request.thread_id, "thread_one");
  assert.equal(calls[1].request.run_id, null);
  assert.equal(calls[1].request.usage_telemetry.total_tokens, 120);
  assert.equal(calls[2].event.thread_id, "thread_one");
  assert.equal(events.length, 1);
  for (const key of ["runId", "workflowNodeId", "idempotencyKey"]) {
    assert.equal(Object.hasOwn(calls[1].request, key), false, `${key} alias must be absent`);
  }
});

test("run context budget uses Rust policy planning and admitted thread event", () => {
  const { calls, store, surface } = compactHarness();

  const result = surface.evaluateContextBudget(store, {
    runId: "run_one",
    request: {
      mode: "simulate",
      thresholds: { max_total_tokens: 100 },
      created_at: "2026-06-13T12:10:00.000Z",
    },
  });

  assert.equal(result.status, "ok");
  assert.equal(result.event.event_kind, "context_budget.evaluated");
  assert.equal(result.event.thread_id, "thread_one");
  assert.equal(result.event.turn_id, "turn_one");
  assert.equal(result.event.event_stream_id, "event_stream_thread_one");
  assert.deepEqual(calls.map((call) => call.name), [
    "usageForRun",
    "evaluateContextBudgetPolicy",
    "appendRuntimeEvent",
  ]);
  assert.equal(calls[1].request.scope, "run");
  assert.equal(calls[1].request.run_id, "run_one");
  assert.equal(calls[1].request.thread_id, "thread_one");
});

test("thread-bound context budget fails closed before usage lookup or event append without Rust planning", () => {
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
  const contextPolicyCore = {
    evaluateContextBudgetPolicy() {
      throw new Error("workflow-only context budget helper should receive the mounted core as budgetRunner");
    },
  };
  const { calls, events, store, surface } = harness({ contextPolicyCore });

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
  assert.equal(policyInput.budgetRunner, contextPolicyCore);
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

test("compaction policy uses Rust planning and event admission before returning route truth", () => {
  const { calls, events, store, surface } = compactHarness();

  const result = surface.evaluateCompactionPolicy(store, {
    threadId: "thread_one",
    request: {
      turn_id: "turn_one",
      context_budget: { status: "blocked" },
      policy: { blocked_action: "compact", approval_required: true },
      created_at: "2026-06-13T12:11:00.000Z",
      eventKind: "RuntimeCompactionPolicy.Retired",
      compactIdempotencyKey: "compaction_execute_idempotency_retired",
    },
  });

  assert.equal(result.status, "waiting");
  assert.equal(result.event.admitted, true);
  assert.equal(result.event.event_kind, "approval.required");
  assert.equal(result.event.event_id, "event_compaction_policy_thread_one_policy_compaction_thread_mock_2026-06-13T12:11:00.000Z");
  assert.equal(result.context_compaction, null);
  assert.deepEqual(calls.map((call) => call.name), [
    "evaluateCompactionPolicy",
    "appendRuntimeEvent",
  ]);
  assert.equal(calls[0].request.thread_id, "thread_one");
  assert.equal(calls[0].request.turn_id, "turn_one");
  assert.equal(calls[1].event.payload.approval_required, true);
  assert.equal(events.length, 1);
  for (const key of ["eventKind", "compactIdempotencyKey"]) {
    assert.equal(Object.hasOwn(calls[0].request, key), false, `${key} alias must be absent`);
  }
});

test("compaction policy executes Rust-owned compactThread when Rust requests compaction", () => {
  const { calls, events, store, surface } = compactHarness();

  const result = surface.evaluateCompactionPolicy(store, {
    threadId: "thread_one",
    request: {
      turn_id: "turn_one",
      context_budget: { status: "blocked" },
      policy: { blocked_action: "compact", approval_required: true, approval_granted: true },
      execute_compaction: true,
      created_at: "2026-06-13T12:12:00.000Z",
    },
  });

  assert.equal(result.status, "compacted");
  assert.equal(result.context_compaction.status, "completed");
  assert.equal(result.context_compaction.target_kind, "agent");
  assert.equal(events.length, 2);
  assert.deepEqual(calls.map((call) => call.name), [
    "evaluateCompactionPolicy",
    "appendRuntimeEvent",
    "agentForThread",
    "planContextCompaction",
    "appendRuntimeEvent",
    "planContextCompactionStateUpdate",
    "writeAgent",
  ]);
  assert.equal(calls[3].request.reason, "trim context after budget block");
  assert.equal(calls[3].request.idempotency_key, "thread:thread_one:compaction-policy:compact:policy_compaction_thread_mock");
  assert.equal(calls[5].request.event_id, result.context_compaction.event_id);
});

test("compaction policy fails closed before event append, compaction execution, or JS persistence without Rust planning", () => {
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
