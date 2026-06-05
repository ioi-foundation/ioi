import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSubagentSurface } from "./runtime-subagent-surface.mjs";

function createStore() {
  const parentAgent = {
    id: "agent_parent",
    cwd: "/tmp/runtime-subagent-surface-test",
  };
  return {
    parentAgent,
    agents: new Map([[parentAgent.id, parentAgent]]),
    events: [],
    eventInputs: [],
    writes: [],
    runs: new Map([
      ["run_1", {
        id: "run_1",
        agentId: "agent_child_1",
        status: "completed",
        result: "Subagent one completed.",
        receipts: [{ id: "receipt_run_1" }],
        trace: {
          taskState: {
            changedObjects: ["file-a"],
            uncertainFacts: [],
            blockers: [],
            evidenceRefs: ["evidence-run-1"],
          },
        },
      }],
      ["run_2", {
        id: "run_2",
        agentId: "agent_child_2",
        status: "completed",
        result: "Subagent two completed.",
        receipts: [{ id: "receipt_run_2" }],
      }],
    ]),
    subagents: new Map([
      ["subagent_2", {
        subagent_id: "subagent_2",
        agent_id: "agent_child_2",
        run_id: "run_2",
        parent_thread_id: "thread_1",
        parent_turn_id: "turn_1",
        role: "reviewer",
        lifecycle_status: "completed",
        created_at: "2026-06-04T12:00:02.000Z",
      }],
      ["subagent_1", {
        subagent_id: "subagent_1",
        agent_id: "agent_child_1",
        run_id: "run_1",
        parent_turn_id: "turn_1",
        parent_thread_id: "thread_1",
        role: "reviewer",
        lifecycle_status: "running",
        output_contract_status: "passed",
        output_contract_validation: { status: "passed" },
        created_at: "2026-06-04T12:00:01.000Z",
      }],
      ["subagent_other", {
        subagent_id: "subagent_other",
        parent_thread_id: "thread_other",
        role: "reviewer",
        lifecycle_status: "running",
        created_at: "2026-06-04T12:00:00.000Z",
      }],
      ["subagent_worker", {
        subagent_id: "subagent_worker",
        parent_thread_id: "thread_1",
        role: "worker",
        lifecycle_status: "running",
        created_at: "2026-06-04T12:00:03.000Z",
      }],
    ]),
    agentForThread(threadId) {
      assert.equal(threadId, "thread_1");
      return parentAgent;
    },
    threadForAgent(agent) {
      assert.equal(agent.id, parentAgent.id);
      return {
        thread_id: "thread_1",
        latest_turn_id: "turn_latest",
      };
    },
    createAgent(input = {}) {
      const agentId = `agent_spawn_${this.agents.size}`;
      const agent = {
        id: agentId,
        cwd: input.local?.cwd ?? parentAgent.cwd,
        requestedModelId: input.model?.id ?? "auto",
        modelRouteId: input.model?.routeId ?? "route.local-first",
        runtimeSessionId: `session_${agentId}`,
      };
      this.agents.set(agentId, agent);
      return agent;
    },
    appendRuntimeEvent(record) {
      const event = {
        ...record,
        event_id: `evt_${this.events.length + 1}`,
        seq: this.events.length + 1,
      };
      this.events.push(event);
      return event;
    },
    getSubagent(threadId, subagentId) {
      return this.surface.getSubagent(this, threadId, subagentId);
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    createRun(agentId, request = {}) {
      const runId = `run_created_${this.runs.size + 1}`;
      const run = {
        id: runId,
        agentId,
        status: "completed",
        result: `Created response: ${request.prompt}`,
        request,
        receipts: [{ id: `receipt_${runId}` }],
        trace: {
          taskState: {
            changedObjects: ["input-response"],
            uncertainFacts: [],
            blockers: [],
            evidenceRefs: [`evidence-${runId}`],
          },
        },
      };
      this.runs.set(runId, run);
      return run;
    },
    cancelRun(runId) {
      const run = this.runs.get(runId);
      const canceled = {
        ...run,
        status: "canceled",
        result: `${run.result} Canceled.`,
        receipts: [...(run.receipts ?? []), { id: `receipt_${runId}_canceled` }],
      };
      this.runs.set(runId, canceled);
      return canceled;
    },
    appendThreadSubagentControlEvent(input) {
      this.eventInputs.push(input);
      return this.surface.appendThreadSubagentControlEvent(this, input);
    },
    subagentProjection(record) {
      return this.surface.subagentProjection(record);
    },
    writeSubagent(record, operationKind) {
      this.subagents.set(record.subagent_id ?? record.subagentId, record);
      this.writes.push({ record, operationKind });
    },
  };
}

function assertCanonicalSubagentBudgetUsageTelemetry(record) {
  assert.equal(
    Object.prototype.hasOwnProperty.call(record, "budget_usage_telemetry"),
    true,
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(record, "budgetUsageTelemetry"),
    false,
  );
}

function assertCanonicalSubagentUsageTelemetry(record) {
  assert.equal(
    Object.prototype.hasOwnProperty.call(record, "usage_telemetry"),
    true,
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(record, "usageTelemetry"),
    false,
  );
}

const retiredSubagentRecordOutputAliasKeys = [
  "schemaVersion",
  "subagentId",
  "agentId",
  "childThreadId",
  "runId",
  "parentThreadId",
  "parentAgentId",
  "parentTurnId",
  "toolPack",
  "modelRouteId",
  "workflowGraphId",
  "workflowNodeId",
  "sessionBootId",
  "lifecycleStatus",
  "restartStatus",
  "restartCount",
  "forkContext",
  "contextMode",
  "maxConcurrency",
  "budgetUsageTelemetry",
  "budgetStatus",
  "budgetPolicyDecision",
  "blockReason",
  "outputContract",
  "outputContractStatus",
  "outputContractValidation",
  "mergePolicy",
  "cancellationInheritance",
  "contextPressureAction",
  "contextPressure",
  "pressure",
  "pressureStatus",
  "alertId",
  "sourceEventId",
  "sourceReceiptRefs",
  "sourcePolicyDecisionRefs",
  "createdAt",
  "updatedAt",
  "eventId",
  "receiptRefs",
  "policyDecisionRefs",
  "evidenceRefs",
  "waitEventId",
  "waitedAt",
  "inputId",
  "inputCount",
  "inputHistory",
  "inputEventId",
  "lastInput",
  "lastInputAt",
  "previousRunIds",
  "resumeId",
  "resumeHistory",
  "resumeEventId",
  "resumedAt",
  "cancellationReason",
  "cancellationInherited",
  "propagatedFromThreadId",
  "cancellationClearedAt",
  "cancellationHistory",
  "assignmentId",
  "assignmentCount",
  "assignmentHistory",
  "assignEventId",
  "assignedAt",
  "targetAgentId",
  "cancelEventId",
  "canceledAt",
];

function assertCanonicalSubagentRecordOutput(record) {
  for (const key of retiredSubagentRecordOutputAliasKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(record, key), false);
  }
}

function assertCanonicalSubagentStoreWrites(store) {
  for (const write of store.writes) {
    assertCanonicalSubagentRecordOutput(write.record);
  }
}

function assertCanonicalPostSpawnSubagentLifecycleStagingRecord(record) {
  assertCanonicalSubagentRecordOutput(record);
}

function assertNoOwnKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.prototype.hasOwnProperty.call(record, key), false);
  }
}

const retiredSubagentListEnvelopeAliasKeys = [
  "schemaVersion",
  "threadId",
  "parentAgentId",
  "activeCount",
];

const retiredSubagentPropagationEnvelopeAliasKeys = [
  "schemaVersion",
  "threadId",
  "parentAgentId",
  "propagationPolicy",
  "candidateCount",
  "canceledCount",
  "skippedCount",
  "canceledSubagents",
  "skippedSubagents",
  "eventRefs",
  "receiptRefs",
];

const retiredSubagentSkippedRecordAliasKeys = [
  "skipReason",
  "cancellationInheritance",
];

const retiredSubagentNestedInputAliasKeys = [
  "schemaVersion",
  "inputId",
  "runId",
  "previousRunId",
  "createdAt",
  "workflowGraphId",
  "workflowNodeId",
];

const retiredSubagentNestedResumeAliasKeys = [
  "schemaVersion",
  "resumeId",
  "runId",
  "previousRunId",
  "previousStatus",
  "modelRouteId",
  "restartCount",
  "createdAt",
  "workflowGraphId",
  "workflowNodeId",
];

const retiredSubagentNestedAssignmentAliasKeys = [
  "schemaVersion",
  "assignmentId",
  "previousRole",
  "targetAgentId",
  "toolPack",
  "modelRouteId",
  "mergePolicy",
  "cancellationInheritance",
  "assignmentCount",
  "createdAt",
  "workflowGraphId",
  "workflowNodeId",
];

const retiredSubagentNestedCancellationAliasKeys = [
  "previousStatus",
  "requestedBy",
  "propagatedFromThreadId",
];

const retiredSubagentErrorDetailAliasKeys = [
  "threadId",
  "subagentId",
  "activeForRole",
  "maxConcurrency",
  "budgetStatus",
  "eventId",
  "receiptRefs",
  "policyDecisionRefs",
];

const retiredSubagentLifecycleResultEnvelopeAliasKeys = ["receiptRefs"];

test("subagent surface lists, filters, and projects thread subagents", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();

  const listed = surface.listSubagents(store, "thread_1", { role: "reviewer" });

  assert.equal(listed.schema_version, "ioi.runtime.subagent-manager.v1");
  assert.equal(listed.parent_agent_id, "agent_parent");
  assert.equal(listed.count, 2);
  assert.equal(listed.active_count, 1);
  assertNoOwnKeys(listed, retiredSubagentListEnvelopeAliasKeys);
  assert.deepEqual(listed.subagents.map((record) => record.subagent_id), ["subagent_1", "subagent_2"]);
  assert.equal(listed.subagents[0].output_contract_status, "passed");
  assertCanonicalSubagentRecordOutput(listed.subagents[0]);
  assertCanonicalSubagentRecordOutput(listed.subagents[1]);
});

test("subagent surface gets records and preserves not-found details", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();

  assert.equal(surface.getSubagent(store, "thread_1", "subagent_1").agent_id, "agent_child_1");
  assert.throws(
    () => surface.getSubagent(store, "thread_1", "subagent_other"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.thread_id === "thread_1" &&
      error.details.subagent_id === "subagent_other" &&
      (assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys), true),
  );
});

test("subagent surface appends daemon-owned control event envelopes", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowMs: () => 1780586400000,
  });
  const record = {
    subagent_id: "subagent_1",
    agent_id: "agent_child_1",
    parent_thread_id: "thread_1",
    parent_turn_id: "turn_1",
    role: "reviewer",
    lifecycle_status: "running",
    budget_status: "exceeded",
    budget_policy_decision: { id: "policy_budget_blocked" },
  };

  const event = surface.appendThreadSubagentControlEvent(store, {
    threadId: "thread_1",
    parentAgent: store.parentAgent,
    record,
    request: {
      source: "agent_studio",
      workflowGraphId: "graph_1",
      receiptRefs: ["receipt_request"],
      policyDecisionRefs: ["policy_request"],
    },
    operation: "cancel",
    status: "canceled",
  });

  assert.equal(event.event_kind, "subagent.canceled");
  assert.equal(event.source_event_kind, "OperatorControl.SubagentCancel");
  assert.equal(event.payload_schema_version, "ioi.runtime.subagent-manager.v1");
  assert.equal(event.turn_id, "turn_1");
  assert.equal(event.workflow_graph_id, "graph_1");
  assert.equal(event.workflow_node_id, "runtime.subagent.cancel");
  assert.equal(event.payload.operation, "cancel");
  assert.deepEqual(event.receipt_refs, [
    "receipt_request",
    "receipt_subagent_cancel_887392bcf20c",
  ]);
  assert.deepEqual(event.policy_decision_refs, ["policy_request", "policy_budget_blocked"]);
  assert.equal(event.fixture_profile, "local_daemon_agentgres_projection");
});

test("subagent surface spawns subagents with source and context metadata", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:15:00.000Z",
    nowMs: () => 1780586100000,
  });
  store.surface = surface;

  const result = surface.spawnSubagent(store, "thread_1", {
    source: "agent_studio",
    prompt: "Research the risky change",
    role: "Planner",
    toolPack: "planning-tools",
    modelRouteId: "route.spawn",
    maxConcurrency: 2,
    forkContext: true,
    mergePolicy: "auto",
    cancellationInheritance: "detach",
    outputContract: ["SUMMARY"],
    workflowGraphId: "graph_spawn",
    workflowNodeId: "node_spawn",
    contextPressureAction: "delegate",
    contextPressure: 0.82,
    pressureStatus: "high",
    alertId: "alert_context",
    sourceEventId: "evt_source",
    receiptRefs: ["receipt_spawn_request"],
    policyDecisionRefs: ["policy_spawn_request"],
  });
  const saved = store.subagents.get("agent_spawn_1");

  assert.equal(result.subagent_id, "agent_spawn_1");
  assert.equal(result.child_thread_id, "thread_spawn_1");
  assert.equal(result.run_id, "run_created_3");
  assert.equal(result.parent_turn_id, "turn_latest");
  assert.equal(result.role, "planner");
  assert.equal(result.tool_pack, "planning-tools");
  assert.equal(result.model_route_id, "route.spawn");
  assert.equal(result.workflow_graph_id, "graph_spawn");
  assert.equal(result.workflow_node_id, "node_spawn");
  assert.equal(result.session_boot_id, "session_agent_spawn_1");
  assert.equal(result.lifecycle_status, "completed");
  assert.equal(result.restart_status, "not_restarted");
  assert.equal(result.context_mode, "forked");
  assert.equal(result.merge_policy, "auto");
  assert.equal(result.cancellation_inheritance, "detach");
  assert.equal(result.context_pressure_action, "delegate");
  assert.equal(result.context_pressure, 0.82);
  assert.equal(result.pressure_status, "high");
  assert.equal(result.source_event_id, "evt_source");
  assert.deepEqual(result.source_receipt_refs, ["receipt_spawn_request"]);
  assert.deepEqual(result.source_policy_decision_refs, ["policy_spawn_request"]);
  assert.equal(result.event.event_kind, "subagent.spawned");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentSpawn");
  assert.equal(result.event.receipt_refs[0], "receipt_spawn_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_spawn_/);
  assert.deepEqual(result.event.policy_decision_refs, [
    "policy_spawn_request",
    "policy_subagent_spawn_allow_09332d1abadc",
  ]);
  assert.equal(store.writes[0].operationKind, "subagent.spawn");
  assert.deepEqual(saved.receipt_refs, [
    "receipt_run_created_3",
    "receipt_spawn_request",
    "receipt_subagent_spawn_09332d1abadc",
  ]);
  assertCanonicalSubagentBudgetUsageTelemetry(result);
  assertCanonicalSubagentRecordOutput(result);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(result);
  assertCanonicalSubagentUsageTelemetry(saved);
  assert.ok(saved.evidence_refs.includes("runtime.subagent.spawn"));
  assert.ok(saved.evidence_refs.includes("policy_spawn_request"));
});

test("subagent surface rejects missing prompt and role concurrency overflow", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;

  assert.throws(
    () => surface.spawnSubagent(store, "thread_1", {}),
    (error) =>
      error.status === 400 &&
      error.code === "subagent_prompt_required" &&
      error.details.thread_id === "thread_1" &&
      (assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys), true),
  );
  assert.throws(
    () =>
      surface.spawnSubagent(store, "thread_1", {
        prompt: "Another reviewer",
        role: "reviewer",
        maxConcurrency: 1,
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.role, "reviewer");
      assert.equal(error.details.active_for_role, 1);
      assert.equal(error.details.max_concurrency, 1);
      assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys);
      return true;
    },
  );
  assert.equal(store.agents.size, 1);
  assert.equal(store.runs.size, 2);
  assert.equal(store.writes.length, 0);
});

test("subagent surface persists blocked spawn and throws budget policy error", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:20:00.000Z",
    nowMs: () => 1780586400000,
  });
  store.surface = surface;

  assert.throws(
    () =>
      surface.spawnSubagent(store, "thread_1", {
        source: "agent_studio",
        prompt: "This delegated task should exceed a tiny token budget.",
        role: "auditor",
        budget: { maxTokens: 1 },
        receiptRefs: ["receipt_spawn_budget_request"],
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.reason, "subagent_budget_exceeded");
      assert.equal(error.details.role, "auditor");
      assert.equal(error.details.subagent.status, "blocked");
      assert.equal(error.details.thread_id, "thread_1");
      assert.equal(error.details.subagent_id, "agent_spawn_1");
      assert.equal(error.details.event_id, "evt_1");
      assert.deepEqual(error.details.receipt_refs, store.events[0].receipt_refs);
      assert.deepEqual(error.details.policy_decision_refs, store.events[0].policy_decision_refs);
      assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys);
      assertCanonicalSubagentBudgetUsageTelemetry(error.details.subagent);
      assertCanonicalSubagentUsageTelemetry(error.details.subagent);
      assertCanonicalSubagentRecordOutput(error.details.subagent);
      return true;
    },
  );
  const saved = store.subagents.get("agent_spawn_1");

  assert.equal(store.writes[0].operationKind, "subagent.spawn");
  assert.equal(saved.lifecycle_status, "blocked");
  assert.equal(saved.block_reason, "subagent_budget_exceeded");
  assert.equal(saved.event_id, "evt_1");
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(saved);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assert.equal(store.events[0].event_kind, "subagent.spawned");
  assert.ok(store.events[0].policy_decision_refs.includes(saved.budget_policy_decision.id));
});

test("subagent surface waits, persists status, and returns result envelope", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:30:00.000Z",
    nowMs: () => 1780587000000,
  });
  store.surface = surface;

  const result = surface.waitSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    receiptRefs: ["receipt_wait_request"],
  });

  assert.equal(result.status, "completed");
  assert.equal(result.subagent.lifecycle_status, "completed");
  assert.equal(result.subagent.wait_event_id, "evt_1");
  assertCanonicalSubagentRecordOutput(result.subagent);
  assert.equal(result.event.event_kind, "subagent.wait_completed");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentWait");
  assert.equal(result.event.receipt_refs[0], "receipt_wait_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_wait_/);
  assert.deepEqual(result.receipt_refs, result.event.receipt_refs);
  assertNoOwnKeys(result, retiredSubagentLifecycleResultEnvelopeAliasKeys);
  assert.equal(store.writes[0].operationKind, "subagent.wait");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(store.subagents.get("subagent_1").waited_at, "2026-06-04T12:30:00.000Z");
  assertCanonicalSubagentRecordOutput(store.subagents.get("subagent_1"));
  assertCanonicalSubagentStoreWrites(store);
});

test("subagent surface reads result with validated output contract projection", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;

  const result = surface.getSubagentResult(store, "thread_1", "subagent_2");

  assert.equal(result.schema_version, "ioi.runtime.subagent-result.v1");
  assert.equal(result.result, "Subagent two completed.");
  assert.equal(result.output_contract_status, "passed");
  assert.equal(result.subagent.output_contract_status, "passed");
  assertCanonicalSubagentRecordOutput(result.subagent);
  assert.deepEqual(result.receipt_refs, ["receipt_run_2"]);
});

test("subagent surface sends input, persists history, and returns event", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:45:00.000Z",
    nowMs: () => 1780587300000,
  });
  store.surface = surface;

  const result = surface.sendSubagentInput(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    message: "Follow up",
    actor: "operator_1",
    workflowGraphId: "graph_input",
    workflowNodeId: "node_input",
    receiptRefs: ["receipt_input_request"],
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.input.message, "Follow up");
  assert.match(result.input.input_id, /^subagent_input_/);
  assert.equal(result.input.run_id, "run_created_3");
  assert.equal(result.input.previous_run_id, "run_1");
  assertNoOwnKeys(result.input, retiredSubagentNestedInputAliasKeys);
  assert.equal(result.run_id, "run_created_3");
  assert.equal(result.previous_run_ids[0], "run_1");
  assert.equal(result.input_count, 1);
  assert.equal(result.input_event_id, "evt_1");
  assert.equal(result.event.event_kind, "subagent.input_sent");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentSendInput");
  assert.equal(result.event.workflow_graph_id, "graph_input");
  assert.equal(result.event.workflow_node_id, "node_input");
  assert.equal(result.event.receipt_refs[0], "receipt_input_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_send_input_/);
  assert.equal(result.result.result, "Created response: Follow up");
  assert.equal(store.writes[0].operationKind, "subagent.input");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(saved.input_history[0].message, "Follow up");
  assertNoOwnKeys(saved.input_history[0], retiredSubagentNestedInputAliasKeys);
  assert.equal(saved.last_input_at, "2026-06-04T12:45:00.000Z");
  assert.deepEqual(saved.receipt_refs, [
    "receipt_run_created_3",
    ...result.event.receipt_refs,
  ]);
  assertCanonicalSubagentBudgetUsageTelemetry(result);
  assertCanonicalSubagentRecordOutput(result);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(result);
  assertCanonicalSubagentUsageTelemetry(saved);
  assert.ok(saved.evidence_refs.includes("runtime.subagent.input"));
  assert.ok(saved.evidence_refs.includes("run_created_3"));
});

test("subagent surface ignores retired usageTelemetry previous usage fallback", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:50:00.000Z",
    nowMs: () => 1780587600000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    budget: { max_tokens: 20 },
    usageTelemetry: {
      cumulative_total_tokens: 999,
      cumulative_cost_estimate_usd: 10,
    },
  });

  const result = surface.sendSubagentInput(store, "thread_1", "subagent_1", {
    message: "short",
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.budget_status, "within_budget");
  assert.equal(saved.budget_status, "within_budget");
  assert.equal(result.budget_usage_telemetry, null);
  assert.equal(saved.budget_usage_telemetry, null);
  assert.ok(result.usage_telemetry.cumulative_total_tokens < 20);
  assertCanonicalSubagentBudgetUsageTelemetry(result);
  assertCanonicalSubagentUsageTelemetry(result);
  assertCanonicalSubagentRecordOutput(result);
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(saved);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
});

test("subagent surface rejects missing input and canceled subagents", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;

  assert.throws(
    () => surface.sendSubagentInput(store, "thread_1", "subagent_1", {}),
    (error) =>
      error.status === 400 &&
      error.code === "subagent_input_required" &&
      error.details.thread_id === "thread_1" &&
      error.details.subagent_id === "subagent_1" &&
      (assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys), true),
  );

  store.subagents.get("subagent_1").lifecycle_status = "canceled";
  assert.throws(
    () =>
      surface.sendSubagentInput(store, "thread_1", "subagent_1", {
        message: "Can you keep going?",
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.message, "Cannot send input to a canceled subagent.");
      assert.equal(error.details.thread_id, "thread_1");
      assert.equal(error.details.subagent_id, "subagent_1");
      assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys);
      return true;
    },
  );
});

test("subagent surface resumes subagents and clears cancellation metadata", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:10:00.000Z",
    nowMs: () => 1780588200000,
  });
  store.surface = surface;
  const canceledRecord = {
    ...store.subagents.get("subagent_1"),
    lifecycle_status: "canceled",
    restart_count: 1,
    cancellation: {
      reason: "operator_cancel",
      previous_status: "running",
      requested_by: "operator_1",
    },
  };
  store.subagents.set("subagent_1", canceledRecord);

  const result = surface.resumeSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    prompt: "Try again",
    role: "Worker",
    modelRouteId: "route.resume",
    actor: "operator_1",
    workflowGraphId: "graph_resume",
    workflowNodeId: "node_resume",
    receiptRefs: ["receipt_resume_request"],
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.status, "completed");
  assert.equal(result.subagent.lifecycle_status, "completed");
  assert.equal(result.subagent.restart_status, "restarted");
  assert.equal(result.subagent.restart_count, 2);
  assert.equal(result.subagent.resume_event_id, "evt_1");
  assert.equal(result.resume.previous_run_id, "run_1");
  assert.equal(result.resume.previous_status, "canceled");
  assert.equal(result.resume.prompt, "Try again");
  assert.equal(result.resume.role, "worker");
  assert.equal(result.resume.model_route_id, "route.resume");
  assert.equal(result.resume.created_at, "2026-06-04T13:10:00.000Z");
  assertNoOwnKeys(result.resume, retiredSubagentNestedResumeAliasKeys);
  assert.equal(result.event.event_kind, "subagent.resumed");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentResume");
  assert.equal(result.event.workflow_graph_id, "graph_resume");
  assert.equal(result.event.workflow_node_id, "node_resume");
  assert.equal(result.event.receipt_refs[0], "receipt_resume_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_resume_/);
  assert.deepEqual(result.receipt_refs, result.event.receipt_refs);
  assertNoOwnKeys(result, retiredSubagentLifecycleResultEnvelopeAliasKeys);
  assert.equal(result.result, "Created response: Try again");
  assert.equal(store.writes[0].operationKind, "subagent.resume");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(saved.cancellation, null);
  assert.equal(saved.cancellation_reason, null);
  assert.equal(saved.cancellation_cleared_at, "2026-06-04T13:10:00.000Z");
  assert.equal(saved.cancellation_history.length, 1);
  assert.equal(saved.resume_history[0].prompt, "Try again");
  assertNoOwnKeys(saved.resume_history[0], retiredSubagentNestedResumeAliasKeys);
  assert.deepEqual(saved.previous_run_ids, ["run_1"]);
  assert.deepEqual(saved.receipt_refs, [
    "receipt_run_created_3",
    ...result.event.receipt_refs,
  ]);
  assertCanonicalSubagentBudgetUsageTelemetry(result.subagent);
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(result.subagent);
  assertCanonicalSubagentUsageTelemetry(saved);
  assertCanonicalSubagentRecordOutput(result.subagent);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assert.ok(saved.evidence_refs.includes("runtime.subagent.resume"));
  assert.ok(saved.evidence_refs.includes("run_created_3"));
});

test("subagent surface persists blocked resume and throws budget policy error", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:20:00.000Z",
    nowMs: () => 1780588800000,
  });
  store.surface = surface;

  assert.throws(
    () =>
      surface.resumeSubagent(store, "thread_1", "subagent_1", {
        source: "agent_studio",
        prompt: "This resume should exceed a tiny token budget.",
        budget: { maxTokens: 1 },
        receiptRefs: ["receipt_resume_budget_request"],
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.reason, "subagent_budget_exceeded");
      assert.equal(error.details.subagent.status, "blocked");
      assert.equal(error.details.thread_id, "thread_1");
      assert.equal(error.details.subagent_id, "subagent_1");
      assert.equal(error.details.event_id, "evt_1");
      assert.deepEqual(error.details.receipt_refs, store.events[0].receipt_refs);
      assert.deepEqual(error.details.policy_decision_refs, store.events[0].policy_decision_refs);
      assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys);
      assertCanonicalSubagentBudgetUsageTelemetry(error.details.subagent);
      assertCanonicalSubagentUsageTelemetry(error.details.subagent);
      assertCanonicalSubagentRecordOutput(error.details.subagent);
      return true;
    },
  );
  const saved = store.subagents.get("subagent_1");

  assert.equal(store.writes[0].operationKind, "subagent.resume");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(saved.lifecycle_status, "blocked");
  assert.equal(saved.block_reason, "subagent_budget_exceeded");
  assert.equal(saved.resume_event_id, "evt_1");
  assertCanonicalSubagentBudgetUsageTelemetry(saved);
  assertCanonicalSubagentUsageTelemetry(saved);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assert.equal(store.events[0].event_kind, "subagent.resumed");
  assert.ok(store.events[0].policy_decision_refs.includes(saved.budget_policy_decision.id));
});

test("subagent surface assigns role metadata and persists assignment history", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:00:00.000Z",
    nowMs: () => 1780587600000,
  });
  store.surface = surface;

  const result = surface.assignSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    role: "Auditor",
    toolPack: "review-tools",
    modelRouteId: "route.audit",
    mergePolicy: "auto",
    cancellationInheritance: "detach",
    targetAgentId: "agent_auditor",
    receiptRefs: ["receipt_assign_request"],
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.role, "auditor");
  assert.equal(result.target_agent_id, "agent_auditor");
  assert.equal(result.tool_pack, "review-tools");
  assert.equal(result.model_route_id, "route.audit");
  assert.equal(result.merge_policy, "auto");
  assert.equal(result.cancellation_inheritance, "detach");
  assert.match(result.assignment.assignment_id, /^subagent_assignment_/);
  assert.equal(result.assignment.previous_role, "reviewer");
  assert.equal(result.assignment.created_at, "2026-06-04T13:00:00.000Z");
  assertNoOwnKeys(result.assignment, retiredSubagentNestedAssignmentAliasKeys);
  assert.equal(result.assignment_history.length, 1);
  assert.equal(result.assign_event_id, "evt_1");
  assertCanonicalSubagentRecordOutput(result);
  assert.equal(result.event.event_kind, "subagent.assigned");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentAssign");
  assert.equal(result.event.receipt_refs[0], "receipt_assign_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_assign_/);
  assert.equal(store.writes[0].operationKind, "subagent.assign");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(saved.role, "auditor");
  assert.ok(saved.evidence_refs.includes("runtime.subagent.assign"));
  assertNoOwnKeys(saved.assignment_history[0], retiredSubagentNestedAssignmentAliasKeys);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
});

test("subagent surface cancels subagents with inherited cancellation metadata", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:30:00.000Z",
    nowMs: () => 1780589400000,
  });
  store.surface = surface;

  const result = surface.cancelSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    reason: "parent_cancel",
    actor: "operator_1",
    inherited: true,
    propagatedFromThreadId: "thread_parent",
    receiptRefs: ["receipt_cancel_request"],
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.status, "canceled");
  assert.equal(result.subagent.lifecycle_status, "canceled");
  assert.equal(result.subagent.cancel_event_id, "evt_1");
  assert.equal(result.subagent.canceled_at, "2026-06-04T13:30:00.000Z");
  assertCanonicalSubagentRecordOutput(result.subagent);
  assert.equal(result.cancellation.reason, "parent_cancel");
  assert.equal(result.cancellation.previous_status, "running");
  assert.equal(result.cancellation.requested_by, "operator_1");
  assert.equal(result.cancellation.inherited, true);
  assert.equal(result.cancellation.propagated_from_thread_id, "thread_parent");
  assertNoOwnKeys(result.cancellation, retiredSubagentNestedCancellationAliasKeys);
  assert.equal(result.event.event_kind, "subagent.canceled");
  assert.equal(result.event.source_event_kind, "OperatorControl.SubagentCancel");
  assert.equal(result.event.receipt_refs[0], "receipt_cancel_request");
  assert.match(result.event.receipt_refs[1], /^receipt_subagent_cancel_/);
  assert.deepEqual(result.receipt_refs, result.event.receipt_refs);
  assertNoOwnKeys(result, retiredSubagentLifecycleResultEnvelopeAliasKeys);
  assert.equal(store.writes[0].operationKind, "subagent.cancel");
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.deepEqual(saved.receipt_refs, [
    "receipt_run_1",
    "receipt_run_1_canceled",
    ...result.event.receipt_refs,
  ]);
  assert.ok(saved.evidence_refs.includes("runtime.subagent.cancel"));
  assertNoOwnKeys(saved.cancellation, retiredSubagentNestedCancellationAliasKeys);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
});

test("subagent surface propagates parent cancellation and reports skipped children", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:40:00.000Z",
    nowMs: () => 1780590000000,
  });
  store.surface = surface;
  store.subagents.set("subagent_2", {
    ...store.subagents.get("subagent_2"),
    cancellationInheritance: "detach",
  });
  store.subagents.set("subagent_worker", {
    ...store.subagents.get("subagent_worker"),
    lifecycle_status: "canceled",
  });

  const result = surface.propagateSubagentCancellation(store, "thread_1", {
    source: "runtime_auto",
    reason: "parent stopped",
    actor: "operator_1",
    receiptRefs: ["receipt_parent_cancel"],
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.schema_version, "ioi.runtime.subagent-manager.v1");
  assert.equal(result.object, "ioi.runtime_subagent_cancellation_propagation");
  assert.equal(result.parent_agent_id, "agent_parent");
  assert.equal(result.source, "runtime_auto");
  assert.equal(result.reason, "parent stopped");
  assert.equal(result.candidate_count, 3);
  assert.equal(result.canceled_count, 1);
  assert.equal(result.skipped_count, 2);
  assertNoOwnKeys(result, retiredSubagentPropagationEnvelopeAliasKeys);
  assert.deepEqual(result.canceled_subagents.map((record) => record.subagent_id), ["subagent_1"]);
  assertCanonicalSubagentRecordOutput(result.canceled_subagents[0]);
  assert.deepEqual(result.skipped_subagents.map((record) => record.skip_reason), [
    "cancellation_inheritance_not_propagate",
    "already_canceled",
  ]);
  assertNoOwnKeys(result.skipped_subagents[0], retiredSubagentSkippedRecordAliasKeys);
  assertNoOwnKeys(result.skipped_subagents[1], retiredSubagentSkippedRecordAliasKeys);
  assert.deepEqual(result.event_refs, ["evt_1"]);
  assert.equal(result.receipt_refs[0], "receipt_parent_cancel");
  assert.match(result.receipt_refs[1], /^receipt_subagent_cancel_/);
  assert.equal(saved.cancellation_inherited, true);
  assert.equal(saved.propagated_from_thread_id, "thread_1");
  assert.equal(saved.cancellation.reason, "parent stopped");
  assertNoOwnKeys(saved.cancellation, retiredSubagentNestedCancellationAliasKeys);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assert.equal(store.events[0].workflow_node_id, "runtime.subagent.cancel.propagated.reviewer");
  assert.equal(store.writes[0].operationKind, "subagent.cancel");
});
