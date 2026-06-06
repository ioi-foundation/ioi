import assert from "node:assert/strict";
import test from "node:test";

import { RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION } from "./runtime-contract-constants.mjs";
import { createRuntimeContextPolicySurface } from "./runtime-context-policy-surface.mjs";

function baseResult(overrides = {}) {
  return {
    status: "passed",
    policy_decision_id: "policy-one",
    receipt_refs: ["receipt-one"],
    policy_decision_refs: ["policy-one"],
    ...overrides,
  };
}

function contextCompactionPlanForRequest(request = {}) {
  const compactHash = "planhash";
  const refOwner = request.run_id ?? request.agent_id;
  return {
    status: "planned",
    thread_id: request.thread_id,
    agent_id: request.agent_id,
    turn_id: request.turn_id ?? undefined,
    run_id: request.run_id ?? undefined,
    session_id: request.session_id ?? undefined,
    workspace_root: request.workspace_root ?? undefined,
    item_id: `${request.turn_id || request.thread_id}:item:context-compact:${compactHash}`,
    idempotency_key: request.idempotency_key ?? `thread:${request.thread_id}:context.compact:${compactHash}`,
    event_source: request.source || "sdk_client",
    source_event_kind: "OperatorControl.Compact",
    event_kind: "context.compacted",
    actor: "user",
    workflow_graph_id: request.workflow_graph_id ?? null,
    workflow_node_id: request.workflow_node_id ?? "runtime.context-compact",
    component_kind: "context_compaction",
    payload_schema_version: "ioi.runtime.context-compaction.v1",
    payload: {
      event_kind: "OperatorControl.Compact",
      reason: request.reason ?? "operator requested context compaction",
      scope: request.scope ?? "thread",
      requested_by: request.requested_by ?? "operator",
      control_surface: request.source || "sdk_client",
      previous_latest_seq: request.previous_latest_seq ?? 0,
      compacted_tokens: 0,
      agent_id: request.agent_id,
      thread_id: request.thread_id,
      turn_id: request.turn_id ?? null,
      run_id: request.run_id ?? null,
      session_id: request.session_id ?? null,
    },
    receipt_refs: [`receipt_${refOwner}_context_compaction_${compactHash}`],
    policy_decision_refs: [`policy_${refOwner}_context_compaction_allow`],
    artifact_refs: [],
    rollback_refs: [],
    redaction_profile: "internal",
    compact_hash: compactHash,
    reason: request.reason ?? "operator requested context compaction",
    scope: request.scope ?? "thread",
    requested_by: request.requested_by ?? "operator",
    previous_latest_seq: request.previous_latest_seq ?? 0,
  };
}

function harness({ contextResult = baseResult(), compactionResult = null, compactionPlan = null } = {}) {
  const calls = [];
  const events = [];
  const run = { id: "run-one", agentId: "agent-one", trace: {} };
  const agent = { id: "agent-one", cwd: "/workspace", runtimeSessionId: "session-one" };
  const surface = createRuntimeContextPolicySurface({
    contextBudgetUsageTelemetryFromRequest(request) {
      calls.push({ name: "contextBudgetUsageTelemetryFromRequest", request });
      return request.usage_telemetry ?? null;
    },
    evaluateContextBudgetPolicy(input) {
      calls.push({ name: "evaluateContextBudgetPolicy", input });
      return { ...contextResult };
    },
    evaluateCompactionPolicyDecision(input) {
      calls.push({ name: "evaluateCompactionPolicyDecision", input });
      return {
        action: "noop",
        policy_decision_id: "compaction-policy-one",
        workflow_graph_id: "graph-one",
        workflow_node_id: "node-one",
        receipt_refs: ["receipt-compaction"],
        policy_decision_refs: ["policy-compaction"],
        ...compactionResult,
      };
    },
    contextPolicyRunner: {
      planContextCompaction(request) {
        calls.push({ name: "planContextCompaction", request });
        return compactionPlan ?? contextCompactionPlanForRequest(request);
      },
    },
    eventStreamIdForThread(threadId) {
      return `stream-${threadId}`;
    },
    fixtureProfileForAgent(inputAgent) {
      return `fixture-${inputAgent.id}`;
    },
    operatorControlSource(source) {
      return source || "operator_control";
    },
    runtimeError(input) {
      const error = new Error(input.message);
      error.details = input;
      return error;
    },
    safeId(value) {
      return String(value).replace(/[^a-z0-9_-]+/gi, "_");
    },
    threadIdForAgent(agentId) {
      return `thread-${agentId}`;
    },
    turnIdForRun(runId) {
      return `turn-${runId}`;
    },
  });
  const store = {
    agents: new Map([[agent.id, agent]]),
    runs: new Map([[run.id, run]]),
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return agent;
    },
    appendRuntimeEvent(event) {
      const projected = { ...event, event_id: `event-${events.length + 1}`, seq: events.length + 1 };
      events.push(projected);
      return projected;
    },
    compactThread(threadId, request) {
      calls.push({ name: "compactThread", threadId, request });
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return run;
    },
    latestRuntimeEventSeq(streamId) {
      calls.push({ name: "latestRuntimeEventSeq", streamId });
      return 7;
    },
    listRuns(agentId) {
      calls.push({ name: "listRuns", agentId });
      return agentId === "agent-one" ? [...this.runs.values()].filter((record) => record.agentId === agentId) : [];
    },
    listUsage(options) {
      calls.push({ name: "listUsage", options });
      return { scope: "list" };
    },
    runtimeEventsForStream(streamId, cursor) {
      calls.push({ name: "runtimeEventsForStream", streamId, cursor });
      return [
        {
          component_kind: "context_compaction",
          event_id: "event-compacted",
          seq: 8,
          artifact_refs: ["artifact-compaction"],
        },
      ];
    },
    threadForAgent(inputAgent) {
      calls.push({ name: "threadForAgent", agentId: inputAgent.id });
      return {
        thread_id: "thread-agent-one",
        latest_turn_id: "turn-run-one",
      };
    },
    usageForRun(runId) {
      calls.push({ name: "usageForRun", runId });
      return { scope: "run", runId };
    },
    usageForThread(threadId) {
      calls.push({ name: "usageForThread", threadId });
      return { scope: "thread", threadId };
    },
    writeAgent(record, operationKind) {
      calls.push({ name: "writeAgent", operationKind, record });
    },
    writeRun(record, operationKind) {
      calls.push({ name: "writeRun", operationKind, record });
    },
  };
  return { calls, events, store, surface };
}

test("context policy surface evaluates context budget and appends thread event", () => {
  const { calls, events, store, surface } = harness({
    contextResult: baseResult({ status: "blocked", policy_decision_id: "policy blocked" }),
  });

  const result = surface.evaluateContextBudget(store, {
    runId: "run-one",
    request: { source: "test", actor: "operator-one" },
  });

  assert.equal(result.event_id, "event-1");
  assert.equal(events[0].event_kind, "policy.blocked");
  assert.equal(events[0].status, "blocked");
  assert.equal(events[0].component_kind, "context_budget");
  assert.equal(events[0].payload_schema_version, RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION);
  assert.equal(events[0].turn_id, "turn-run-one");
  assert.equal(events[0].fixture_profile, "fixture-agent-one");
  assert.equal(calls.find((call) => call.name === "evaluateContextBudgetPolicy").input.request.scope, "run");
  assert.deepEqual(calls.map((call) => call.name).slice(0, 4), [
    "getRun",
    "contextBudgetUsageTelemetryFromRequest",
    "usageForRun",
    "evaluateContextBudgetPolicy",
  ]);
});

test("context policy surface can evaluate workflow-only budget without appending event", () => {
  const { events, store, surface } = harness();

  const result = surface.evaluateContextBudget(store, {
    request: { usage_telemetry: { total_tokens: 12 } },
  });

  assert.equal(result.status, "passed");
  assert.deepEqual(events, []);
});

test("compaction policy surface appends approval or compact events", () => {
  const { calls, events, store, surface } = harness({
    compactionResult: {
      action: "compact",
      approval_satisfied: true,
      execute_compaction: true,
      compact_reason: "trim history",
      compact_scope: "thread",
      compact_workflow_node_id: "node-compact",
      workflow_graph_id: "graph-compact",
      workflow_node_id: "node-policy",
      policy_decision_id: "policy compact",
    },
  });

  const result = surface.evaluateCompactionPolicy(store, {
    threadId: "thread-agent-one",
    request: { source: "test-source" },
  });

  assert.equal(result.compaction_executed, true);
  assert.equal(result.compaction_event_id, "event-compacted");
  assert.equal(events[0].event_kind, "compaction_policy.evaluated");
  assert.equal(events[0].status, "completed");
  assert.deepEqual(events[0].artifact_refs, ["artifact-compaction"]);
  assert.deepEqual(calls.find((call) => call.name === "compactThread").request, {
    reason: "trim history",
    scope: "thread",
    turn_id: "turn-run-one",
    source: "test-source",
    actor: "operator",
    workflow_graph_id: "graph-compact",
    workflow_node_id: "node-compact",
    idempotency_key: "thread:thread-agent-one:compaction-policy:compact:policy_compact",
  });
});

test("compaction policy surface handles required thread and approval-required status", () => {
  const { events, store, surface } = harness({
    compactionResult: {
      action: "approval_required",
      approval_id: "approval-one",
      policy_decision_id: "policy approval",
    },
  });

  assert.throws(() => surface.evaluateCompactionPolicy(store, { request: {} }), /requires a thread id/);
  const result = surface.evaluateCompactionPolicy(store, {
    threadId: "thread-agent-one",
    request: { actor: "operator-two" },
  });

  assert.equal(result.event_id, "event-1");
  assert.equal(events[0].event_kind, "approval.required");
  assert.equal(events[0].status, "waiting");
  assert.equal(events[0].approval_id, "approval-one");
});

test("context policy surface compacts latest run and records operator control", () => {
  const { calls, events, store, surface } = harness();

  const result = surface.compactThread(store, "thread-agent-one", {
    source: "agent_studio",
    reason: "trim context",
    scope: "thread",
    actor: "operator-one",
    workflowGraphId: "graph-compact",
    workflowNodeId: "node-compact",
  });
  const savedRun = store.runs.get("run-one");

  assert.equal(result.thread_id, "thread-agent-one");
  assert.equal(events[0].event_kind, "context.compacted");
  assert.equal(events[0].source_event_kind, "OperatorControl.Compact");
  assert.equal(events[0].component_kind, "context_compaction");
  assert.equal(events[0].payload_schema_version, "ioi.runtime.context-compaction.v1");
  assert.equal(events[0].turn_id, "turn-run-one");
  assert.equal(events[0].workflow_graph_id, "graph-compact");
  assert.equal(events[0].workflow_node_id, "node-compact");
  assert.equal(events[0].payload.session_id, "session-one");
  assert.equal(events[0].fixture_profile, "fixture-agent-one");
  assert.match(events[0].receipt_refs[0], /^receipt_run-one_context_compaction_/);
  assert.equal(calls.find((call) => call.name === "planContextCompaction").request.reason, "trim context");
  assert.equal(savedRun.trace.contextCompaction.reason, "trim context");
  assert.equal(savedRun.operatorControls[0].control, "compact");
  assert.equal(calls.find((call) => call.name === "writeRun").operationKind, "thread.compact");
});

test("context policy surface compacts runless thread by touching agent state", () => {
  const { calls, events, store, surface } = harness();
  store.runs.clear();

  const result = surface.compactThread(store, "thread-agent-one", {
    reason: "runless compact",
  });
  const savedAgent = store.agents.get("agent-one");

  assert.equal(result.thread_id, "thread-agent-one");
  assert.equal(events[0].turn_id, "");
  assert.equal(events[0].payload.run_id, null);
  assert.match(events[0].receipt_refs[0], /^receipt_agent-one_context_compaction_/);
  assert.equal(savedAgent.updatedAt, events[0].created_at);
  assert.equal(calls.find((call) => call.name === "writeAgent").operationKind, "thread.compact");
});
