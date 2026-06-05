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

function assertCanonicalSpawnSubagentStagingRecord(record) {
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
  const canonicalAliasListed = surface.listSubagents(store, "thread_1", {
    subagent_role: "worker",
  });

  assert.equal(listed.schema_version, "ioi.runtime.subagent-manager.v1");
  assert.equal(listed.parent_agent_id, "agent_parent");
  assert.equal(listed.count, 2);
  assert.equal(listed.active_count, 1);
  assertNoOwnKeys(listed, retiredSubagentListEnvelopeAliasKeys);
  assert.deepEqual(listed.subagents.map((record) => record.subagent_id), ["subagent_1", "subagent_2"]);
  assert.equal(listed.subagents[0].output_contract_status, "passed");
  assertCanonicalSubagentRecordOutput(listed.subagents[0]);
  assertCanonicalSubagentRecordOutput(listed.subagents[1]);
  assert.deepEqual(
    canonicalAliasListed.subagents.map((record) => record.subagent_id),
    ["subagent_worker"],
  );
});

test("subagent list ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();

  const listed = surface.listSubagents(store, "thread_1", {
    subagentRole: "worker",
  });
  const canonicalWins = surface.listSubagents(store, "thread_1", {
    role: "reviewer",
    subagentRole: "worker",
  });

  assert.deepEqual(listed.subagents.map((record) => record.subagent_id), [
    "subagent_1",
    "subagent_2",
    "subagent_worker",
  ]);
  assert.deepEqual(canonicalWins.subagents.map((record) => record.subagent_id), [
    "subagent_1",
    "subagent_2",
  ]);
});

test("subagent list and lookup ignore retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.subagents.set("subagent_alias_poison", {
    subagent_id: "subagent_alias_poison",
    agent_id: "agent_alias_poison",
    run_id: "run_2",
    parent_thread_id: "thread_other",
    parentThreadId: "thread_1",
    role: "reviewer",
    lifecycle_status: "running",
    created_at: "2026-06-04T12:00:04.000Z",
    createdAt: "1999-01-01T00:00:00.000Z",
  });
  store.subagents.set("subagent_sort_poison", {
    subagent_id: "subagent_sort_poison",
    agent_id: "agent_sort_poison",
    run_id: "run_2",
    parent_thread_id: "thread_1",
    parentThreadId: "thread_other",
    role: "reviewer",
    lifecycle_status: "running",
    created_at: "2026-06-04T12:00:04.000Z",
    createdAt: "1900-01-01T00:00:00.000Z",
  });

  const listed = surface.listSubagents(store, "thread_1", { role: "reviewer" });

  assert.deepEqual(listed.subagents.map((record) => record.subagent_id), [
    "subagent_1",
    "subagent_2",
    "subagent_sort_poison",
  ]);
  assert.equal(
    listed.subagents.some((record) => record.subagent_id === "subagent_alias_poison"),
    false,
  );
  assert.equal(
    surface.getSubagent(store, "thread_1", "subagent_sort_poison").subagent_id,
    "subagent_sort_poison",
  );
  assert.throws(
    () => surface.getSubagent(store, "thread_1", "subagent_alias_poison"),
    (error) =>
      error.status === 404 &&
      error.details.thread_id === "thread_1" &&
      error.details.subagent_id === "subagent_alias_poison" &&
      (assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys), true),
  );
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
      workflow_graph_id: "graph_1",
      receipt_refs: ["receipt_request"],
      policy_decision_refs: ["policy_request"],
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

test("subagent control event ignores retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowMs: () => 1780586400000,
  });
  const event = surface.appendThreadSubagentControlEvent(store, {
    threadId: "thread_1",
    parentAgent: store.parentAgent,
    record: {
      subagent_id: "subagent_1",
      subagentId: "subagent_alias",
      agent_id: "agent_child_1",
      parent_thread_id: "thread_1",
      parentTurnId: "turn_alias",
      workflowGraphId: "graph_alias",
      workflowNodeId: "node_alias",
      role: "reviewer",
      lifecycle_status: "running",
      budgetStatus: { status: "exceeded" },
      budgetPolicyDecision: { id: "policy_alias" },
    },
    request: {
      source: "agent_studio",
    },
    operation: "cancel",
    status: "canceled",
  });

  assert.equal(event.turn_id, "turn_latest");
  assert.match(event.item_id, /:subagent:cancel:subagent_1$/);
  assert.match(event.idempotency_key, /:subagent_1:/);
  assert.equal(event.workflow_graph_id, null);
  assert.equal(event.workflow_node_id, "runtime.subagent.cancel");
  assert.deepEqual(event.policy_decision_refs, ["policy_subagent_cancel_allow_887392bcf20c"]);
});

test("subagent control event ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowMs: () => 1780586400000,
  });

  const event = surface.appendThreadSubagentControlEvent(store, {
    threadId: "thread_1",
    parentAgent: store.parentAgent,
    record: {
      subagent_id: "subagent_1",
      agent_id: "agent_child_1",
      parent_thread_id: "thread_1",
      role: "reviewer",
      lifecycle_status: "running",
    },
    request: {
      source: "agent_studio",
      workflow_graph_id: "graph_canonical",
      workflowGraphId: "graph_alias",
      workflow_node_id: "node_canonical",
      workflowNodeId: "node_alias",
      receipt_refs: ["receipt_canonical"],
      receiptRefs: ["receipt_alias"],
      policy_decision_refs: ["policy_canonical"],
      policyDecisionRefs: ["policy_alias"],
      idempotency_key: "idempotency_canonical",
      idempotencyKey: "idempotency_alias",
    },
    operation: "cancel",
    status: "canceled",
  });

  assert.equal(event.workflow_graph_id, "graph_canonical");
  assert.equal(event.workflow_node_id, "node_canonical");
  assert.equal(event.idempotency_key, "idempotency_canonical");
  assert.equal(event.receipt_refs.includes("receipt_canonical"), true);
  assert.equal(event.receipt_refs.includes("receipt_alias"), false);
  assert.equal(event.policy_decision_refs.includes("policy_canonical"), true);
  assert.equal(event.policy_decision_refs.includes("policy_alias"), false);
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
    tool_pack: "planning-tools",
    model_route_id: "route.spawn",
    max_concurrency: 2,
    fork_context: true,
    merge_policy: "auto",
    cancellation_inheritance: "detach",
    output_contract: ["SUMMARY"],
    workflow_graph_id: "graph_spawn",
    workflow_node_id: "node_spawn",
    context_pressure_action: "delegate",
    context_pressure: 0.82,
    pressure_status: "high",
    alert_id: "alert_context",
    source_event_id: "evt_source",
    receipt_refs: ["receipt_spawn_request"],
    policy_decision_refs: ["policy_spawn_request"],
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
  assertCanonicalSpawnSubagentStagingRecord(store.eventInputs[0].record);
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

test("subagent spawn ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:17:00.000Z",
    nowMs: () => 1780586220000,
  });
  store.surface = surface;

  const result = surface.spawnSubagent(store, "thread_1", {
    source: "agent_studio",
    prompt: "Canonical spawn request",
    message: "Message alias spawn request",
    input: "Input alias spawn request",
    subagent_prompt: "Snake alias spawn request",
    subagentPrompt: "Alias spawn request",
    role: "Planner",
    subagentRole: "Reviewer",
    tool_pack: "canonical-tools",
    toolPack: "alias-tools",
    model_route_id: "route.spawn.canonical",
    modelRouteId: "route.spawn.alias",
    max_concurrency: 3,
    maxConcurrency: 1,
    fork_context: true,
    forkContext: false,
    merge_policy: "canonical-merge",
    mergePolicy: "alias-merge",
    cancellation_inheritance: "detach",
    cancellationInheritance: "propagate",
    output_contract: ["SUMMARY"],
    outputContract: ["MISSING_SECTION"],
    workflow_graph_id: "graph_spawn_canonical",
    workflowGraphId: "graph_spawn_alias",
    workflow_node_id: "node_spawn_canonical",
    workflowNodeId: "node_spawn_alias",
    parent_turn_id: "turn_spawn_canonical",
    parentTurnId: "turn_spawn_alias",
    context_pressure_action: "delegate",
    contextPressureAction: "alias-action",
    context_pressure: 0.42,
    contextPressure: 0.99,
    pressure_status: "medium",
    pressureStatus: "alias-pressure",
    alert_id: "alert_canonical",
    alertId: "alert_alias",
    source_event_id: "evt_canonical",
    sourceEventId: "evt_alias",
    receipt_refs: ["receipt_spawn_canonical"],
    receiptRefs: ["receipt_spawn_alias"],
    policy_decision_refs: ["policy_spawn_canonical"],
    policyDecisionRefs: ["policy_spawn_alias"],
  });
  const saved = store.subagents.get("agent_spawn_1");
  const createdRun = store.runs.get("run_created_3");

  assert.equal(createdRun.request.prompt, "Canonical spawn request");
  assert.equal(result.role, "planner");
  assert.equal(result.tool_pack, "canonical-tools");
  assert.equal(result.model_route_id, "route.spawn.canonical");
  assert.equal(result.max_concurrency, 3);
  assert.equal(result.context_mode, "forked");
  assert.equal(result.merge_policy, "canonical-merge");
  assert.equal(result.cancellation_inheritance, "detach");
  assert.equal(result.output_contract_status, "passed");
  assert.equal(result.workflow_graph_id, "graph_spawn_canonical");
  assert.equal(result.workflow_node_id, "node_spawn_canonical");
  assert.equal(result.parent_turn_id, "turn_spawn_canonical");
  assert.equal(result.context_pressure_action, "delegate");
  assert.equal(result.context_pressure, 0.42);
  assert.equal(result.pressure_status, "medium");
  assert.equal(result.alert_id, "alert_canonical");
  assert.equal(result.source_event_id, "evt_canonical");
  assert.deepEqual(result.source_receipt_refs, ["receipt_spawn_canonical"]);
  assert.deepEqual(result.source_policy_decision_refs, ["policy_spawn_canonical"]);
  assert.equal(result.event.receipt_refs.includes("receipt_spawn_canonical"), true);
  assert.equal(result.event.receipt_refs.includes("receipt_spawn_alias"), false);
  assert.equal(result.event.policy_decision_refs.includes("policy_spawn_canonical"), true);
  assert.equal(result.event.policy_decision_refs.includes("policy_spawn_alias"), false);
  assert.equal(saved.evidence_refs.includes("receipt_spawn_canonical"), true);
  assert.equal(saved.evidence_refs.includes("receipt_spawn_alias"), false);
  assertCanonicalSpawnSubagentStagingRecord(store.eventInputs[0].record);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
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
        max_concurrency: 1,
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
        receipt_refs: ["receipt_spawn_budget_request"],
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
  assertCanonicalSpawnSubagentStagingRecord(store.eventInputs[0].record);
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
    receipt_refs: ["receipt_wait_request"],
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

test("subagent wait and result reads ignore retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:35:00.000Z",
    nowMs: () => 1780587100000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    output_contract: ["SUMMARY"],
    runId: "run_2",
    outputContract: ["MISSING_SECTION"],
    lifecycleStatus: "blocked",
  });
  store.subagents.set("subagent_2", {
    ...store.subagents.get("subagent_2"),
    output_contract: ["SUMMARY"],
    runId: "run_1",
    outputContract: ["MISSING_SECTION"],
  });

  const waited = surface.waitSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
  });
  const read = surface.getSubagentResult(store, "thread_1", "subagent_2");

  assert.equal(waited.status, "completed");
  assert.equal(waited.output_contract_status, "passed");
  assert.equal(waited.result, "Subagent one completed.");
  assert.equal(store.subagents.get("subagent_1").waited_at, "2026-06-04T12:35:00.000Z");
  assert.equal(read.result, "Subagent two completed.");
  assert.equal(read.output_contract_status, "passed");
  assert.equal(read.subagent.output_contract_status, "passed");
  assertCanonicalSubagentRecordOutput(waited.subagent);
  assertCanonicalSubagentRecordOutput(read.subagent);
  assertCanonicalSubagentStoreWrites(store);
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
    input: "Follow up",
    actor: "operator_1",
    workflow_graph_id: "graph_input",
    workflow_node_id: "node_input",
    receipt_refs: ["receipt_input_request"],
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

test("subagent send input ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:46:00.000Z",
    nowMs: () => 1780587360000,
  });
  store.surface = surface;

  assert.throws(
    () =>
      surface.sendSubagentInput(store, "thread_1", "subagent_1", {
        message: "Message alias-only follow up",
        prompt: "Prompt alias-only follow up",
        text: "Text alias-only follow up",
        subagent_input: "Snake alias-only follow up",
        subagentInput: "Alias-only follow up",
      }),
    (error) =>
      error.status === 400 &&
      error.code === "subagent_input_required" &&
      (assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys), true),
  );

  const result = surface.sendSubagentInput(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    input: "Canonical follow up",
    message: "Message alias follow up",
    prompt: "Prompt alias follow up",
    text: "Text alias follow up",
    subagent_input: "Snake alias follow up",
    subagentInput: "Alias follow up",
    workflow_graph_id: "graph_input_canonical",
    workflow_node_id: "node_input_canonical",
    workflowGraphId: "graph_input_alias",
    workflowNodeId: "node_input_alias",
  });

  assert.equal(result.input.message, "Canonical follow up");
  assert.equal(result.event.workflow_graph_id, "graph_input_canonical");
  assert.equal(result.event.workflow_node_id, "node_input_canonical");
  assert.equal(result.input.workflow_graph_id, "graph_input_canonical");
  assert.equal(result.input.workflow_node_id, "node_input_canonical");
  assertNoOwnKeys(result.input, retiredSubagentNestedInputAliasKeys);
});

test("subagent send input ignores retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T12:47:00.000Z",
    nowMs: () => 1780587420000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    output_contract: ["SUMMARY"],
    budget: { max_tokens: 1000 },
    input_history: [],
    previous_run_ids: [],
    evidence_refs: ["evidence_canonical"],
    lifecycleStatus: "canceled",
    runId: "run_2",
    agentId: "agent_alias_child",
    outputContract: ["MISSING_SECTION"],
    subagentBudget: { max_tokens: 1 },
    inputHistory: [{ input_id: "input_alias" }],
    previousRunIds: ["run_alias"],
    evidenceRefs: ["evidence_alias"],
  });

  const result = surface.sendSubagentInput(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    input: "Canonical follow up",
  });
  const saved = store.subagents.get("subagent_1");
  const createdRun = store.runs.get("run_created_3");

  assert.equal(result.status, "completed");
  assert.equal(result.input.previous_run_id, "run_1");
  assert.equal(result.previous_run_ids.includes("run_alias"), false);
  assert.deepEqual(saved.previous_run_ids, ["run_1"]);
  assert.equal(saved.input_count, 1);
  assert.equal(saved.input_history[0].message, "Canonical follow up");
  assert.equal(saved.output_contract_status, "passed");
  assert.equal(saved.budget_status, "within_budget");
  assert.equal(createdRun.agentId, "agent_child_1");
  assert.ok(saved.evidence_refs.includes("evidence_canonical"));
  assert.equal(saved.evidence_refs.includes("evidence_alias"), false);
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
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
    input: "short",
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
        input: "Can you keep going?",
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
    model_route_id: "route.resume",
    actor: "operator_1",
    workflow_graph_id: "graph_resume",
    workflow_node_id: "node_resume",
    receipt_refs: ["receipt_resume_request"],
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

test("subagent resume ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:12:00.000Z",
    nowMs: () => 1780588320000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    lifecycle_status: "canceled",
    model_route_id: "route.resume.record",
    restart_count: 1,
  });

  const result = surface.resumeSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    resume_prompt: "Canonical resume prompt",
    resumePrompt: "Alias resume prompt",
    role: "Worker",
    subagentRole: "AliasRole",
    model_route_id: "route.resume.canonical",
    modelRouteId: "route.resume.alias",
    subagentModelRoute: "route.resume.subagent.alias",
    workflow_graph_id: "graph_resume_canonical",
    workflow_node_id: "node_resume_canonical",
    workflowGraphId: "graph_resume_alias",
    workflowNodeId: "node_resume_alias",
  });
  const saved = store.subagents.get("subagent_1");
  const createdRun = store.runs.get("run_created_3");

  assert.equal(result.resume.prompt, "Canonical resume prompt");
  assert.equal(result.resume.role, "worker");
  assert.equal(result.resume.model_route_id, "route.resume.canonical");
  assert.equal(result.resume.workflow_graph_id, "graph_resume_canonical");
  assert.equal(result.resume.workflow_node_id, "node_resume_canonical");
  assert.equal(result.event.workflow_graph_id, "graph_resume_canonical");
  assert.equal(result.event.workflow_node_id, "node_resume_canonical");
  assert.equal(createdRun.request.prompt, "Canonical resume prompt");
  assert.equal(createdRun.request.options.receiver, "worker");
  assert.equal(createdRun.request.options.model.routeId, "route.resume.canonical");
  assert.equal(saved.resume_history[0].prompt, "Canonical resume prompt");
  assertNoOwnKeys(result.resume, retiredSubagentNestedResumeAliasKeys);
});

test("subagent resume ignores retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:15:00.000Z",
    nowMs: () => 1780588500000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    lifecycle_status: "canceled",
    model_route_id: "route.resume.canonical",
    output_contract: ["SUMMARY"],
    budget: { max_tokens: 1000 },
    restart_count: 1,
    resume_history: [],
    cancellation_history: [],
    previous_run_ids: [],
    evidence_refs: ["evidence_resume_canonical"],
    cancellation: {
      reason: "operator_cancel",
      previous_status: "running",
      requested_by: "operator_1",
    },
    runId: "run_2",
    lifecycleStatus: "running",
    agentId: "agent_alias_resume",
    modelRouteId: "route.resume.alias",
    outputContract: ["MISSING_SECTION"],
    subagentBudget: { max_tokens: 1 },
    restartCount: 99,
    resumeHistory: [{ resume_id: "resume_alias" }],
    cancellationHistory: [{ reason: "alias_cancel" }],
    previousRunIds: ["run_alias"],
    evidenceRefs: ["evidence_resume_alias"],
  });

  const result = surface.resumeSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    prompt: "Try again canonical",
  });
  const saved = store.subagents.get("subagent_1");
  const createdRun = store.runs.get("run_created_3");

  assert.equal(result.resume.previous_run_id, "run_1");
  assert.equal(result.resume.previous_status, "canceled");
  assert.equal(result.resume.model_route_id, "route.resume.canonical");
  assert.equal(result.resume.restart_count, 2);
  assert.equal(result.result, "Created response: Try again canonical");
  assert.equal(saved.budget_status, "within_budget");
  assert.equal(createdRun.agentId, "agent_child_1");
  assert.equal(createdRun.request.options.model.routeId, "route.resume.canonical");
  assert.deepEqual(saved.previous_run_ids, ["run_1"]);
  assert.equal(saved.resume_history.length, 1);
  assert.equal(saved.cancellation_history.length, 1);
  assert.equal(saved.evidence_refs.includes("evidence_resume_canonical"), true);
  assert.equal(saved.evidence_refs.includes("evidence_resume_alias"), false);
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
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
        receipt_refs: ["receipt_resume_budget_request"],
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
    tool_pack: "review-tools",
    model_route_id: "route.audit",
    merge_policy: "auto",
    cancellation_inheritance: "detach",
    target_agent_id: "agent_auditor",
    workflow_graph_id: "graph_assign",
    workflow_node_id: "node_assign",
    receipt_refs: ["receipt_assign_request"],
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
  assert.equal(result.event.workflow_graph_id, "graph_assign");
  assert.equal(result.event.workflow_node_id, "node_assign");
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

test("subagent assign ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:03:00.000Z",
    nowMs: () => 1780587780000,
  });
  store.surface = surface;

  const result = surface.assignSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    subagent_role: "Auditor",
    subagentRole: "AliasRole",
    tool_pack: "canonical-tools",
    toolPack: "alias-tools",
    subagentToolPack: "subagent-alias-tools",
    model_route_id: "route.assign.canonical",
    modelRouteId: "route.assign.alias",
    subagentModelRoute: "route.assign.subagent.alias",
    merge_policy: "canonical-merge",
    mergePolicy: "alias-merge",
    cancellation_inheritance: "detach",
    cancellationInheritance: "propagate",
    target_agent_id: "agent_canonical_assign",
    targetAgentId: "agent_alias_assign",
    workflow_graph_id: "graph_assign_canonical",
    workflow_node_id: "node_assign_canonical",
    workflowGraphId: "graph_assign_alias",
    workflowNodeId: "node_assign_alias",
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.role, "auditor");
  assert.equal(result.target_agent_id, "agent_canonical_assign");
  assert.equal(result.tool_pack, "canonical-tools");
  assert.equal(result.model_route_id, "route.assign.canonical");
  assert.equal(result.merge_policy, "canonical-merge");
  assert.equal(result.cancellation_inheritance, "detach");
  assert.equal(result.assignment.workflow_graph_id, "graph_assign_canonical");
  assert.equal(result.assignment.workflow_node_id, "node_assign_canonical");
  assert.equal(result.event.workflow_graph_id, "graph_assign_canonical");
  assert.equal(result.event.workflow_node_id, "node_assign_canonical");
  assert.equal(saved.assignment_history[0].tool_pack, "canonical-tools");
  assertNoOwnKeys(result.assignment, retiredSubagentNestedAssignmentAliasKeys);
});

test("subagent assign ignores retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:05:00.000Z",
    nowMs: () => 1780587900000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    tool_pack: "canonical-tools",
    model_route_id: "route.assign.canonical",
    merge_policy: "canonical-merge",
    cancellation_inheritance: "detach",
    agent_id: "agent_child_1",
    assignment_count: 1,
    assignment_history: [],
    output_contract: ["SUMMARY"],
    evidence_refs: ["evidence_assign_canonical"],
    toolPack: "alias-tools",
    modelRouteId: "route.assign.alias",
    mergePolicy: "alias-merge",
    cancellationInheritance: "propagate",
    agentId: "agent_alias_assign",
    assignmentCount: 99,
    assignmentHistory: [{ assignment_id: "assignment_alias" }],
    runId: "run_2",
    outputContract: ["MISSING_SECTION"],
    evidenceRefs: ["evidence_assign_alias"],
  });

  const result = surface.assignSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    role: "Lead",
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.role, "lead");
  assert.equal(result.target_agent_id, "agent_child_1");
  assert.equal(result.tool_pack, "canonical-tools");
  assert.equal(result.model_route_id, "route.assign.canonical");
  assert.equal(result.merge_policy, "canonical-merge");
  assert.equal(result.cancellation_inheritance, "detach");
  assert.equal(result.assignment.assignment_count, 2);
  assert.equal(result.result.result, "Subagent one completed.");
  assert.equal(saved.output_contract_status, "passed");
  assert.equal(saved.assignment_history.length, 1);
  assert.equal(saved.evidence_refs.includes("evidence_assign_canonical"), true);
  assert.equal(saved.evidence_refs.includes("evidence_assign_alias"), false);
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
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
    propagated_from_thread_id: "thread_parent",
    receipt_refs: ["receipt_cancel_request"],
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

test("subagent cancel ignores retired camelCase request aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:32:00.000Z",
    nowMs: () => 1780589520000,
  });
  store.surface = surface;

  const result = surface.cancelSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    actor: "operator_1",
    cancellationReason: "alias_cancel",
    cancellationInherited: true,
    propagatedFromThreadId: "thread_alias",
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.cancellation.reason, "operator_cancel");
  assert.equal(result.cancellation.inherited, false);
  assert.equal(result.cancellation.propagated_from_thread_id, null);
  assert.equal(saved.cancellation_reason, "operator_cancel");
  assert.equal(saved.cancellation_inherited, false);
  assert.equal(saved.propagated_from_thread_id, null);
  assertNoOwnKeys(result.cancellation, retiredSubagentNestedCancellationAliasKeys);
});

test("subagent cancel ignores retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:35:00.000Z",
    nowMs: () => 1780589700000,
  });
  store.surface = surface;
  store.subagents.set("subagent_1", {
    ...store.subagents.get("subagent_1"),
    lifecycle_status: "running",
    run_id: "run_1",
    output_contract: ["SUMMARY"],
    evidence_refs: ["evidence_cancel_canonical"],
    lifecycleStatus: "completed",
    runId: "run_2",
    outputContract: ["MISSING_SECTION"],
    evidenceRefs: ["evidence_cancel_alias"],
  });

  const result = surface.cancelSubagent(store, "thread_1", "subagent_1", {
    source: "agent_studio",
    reason: "operator_cancel",
    actor: "operator_1",
  });
  const saved = store.subagents.get("subagent_1");

  assert.equal(result.status, "canceled");
  assert.equal(result.run_id, "run_1");
  assert.equal(result.result, "Subagent one completed. Canceled.");
  assert.equal(result.cancellation.previous_status, "running");
  assert.equal(saved.output_contract_status, "passed");
  assert.equal(store.runs.get("run_1").status, "canceled");
  assert.equal(store.runs.get("run_2").status, "completed");
  assert.equal(saved.evidence_refs.includes("evidence_cancel_canonical"), true);
  assert.equal(saved.evidence_refs.includes("evidence_cancel_alias"), false);
  assertCanonicalPostSpawnSubagentLifecycleStagingRecord(store.eventInputs[0].record);
  assertNoOwnKeys(saved.cancellation, retiredSubagentNestedCancellationAliasKeys);
  assertCanonicalSubagentRecordOutput(saved);
  assertCanonicalSubagentStoreWrites(store);
});

test("subagent surface propagates parent cancellation and ignores retired record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface({
    nowIso: () => "2026-06-04T13:40:00.000Z",
    nowMs: () => 1780590000000,
  });
  store.surface = surface;
  store.subagents.set("subagent_2", {
    ...store.subagents.get("subagent_2"),
    cancellation_inheritance: "detach",
    cancellationInheritance: "propagate",
  });
  store.subagents.set("subagent_worker", {
    ...store.subagents.get("subagent_worker"),
    lifecycle_status: "canceled",
    lifecycleStatus: "running",
    createdAt: "1900-01-01T00:00:00.000Z",
  });
  store.subagents.set("subagent_parent_alias_poison", {
    subagent_id: "subagent_parent_alias_poison",
    agent_id: "agent_parent_alias_poison",
    run_id: "run_2",
    parent_thread_id: "thread_other",
    parentThreadId: "thread_1",
    role: "reviewer",
    lifecycle_status: "running",
    created_at: "2026-06-04T12:00:04.000Z",
  });

  const result = surface.propagateSubagentCancellation(store, "thread_1", {
    source: "runtime_auto",
    reason: "parent stopped",
    actor: "operator_1",
    workflow_node_id: "node_parent_cancel",
    workflowNodeId: "node_parent_cancel_alias",
    receipt_refs: ["receipt_parent_cancel"],
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
  assert.equal(
    result.canceled_subagents.some((record) => record.subagent_id === "subagent_parent_alias_poison"),
    false,
  );
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
  assert.equal(store.events[0].workflow_node_id, "node_parent_cancel");
  assert.equal(
    Object.prototype.hasOwnProperty.call(store.eventInputs[0].request, "workflowNodeId"),
    false,
  );
  assert.equal(store.writes[0].operationKind, "subagent.cancel");
});
