import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSubagentSurface } from "./runtime-subagent-surface.mjs";

function createStore() {
  const parentAgent = {
    id: "agent_parent",
    cwd: "/tmp/runtime-subagent-surface-test",
  };
  const store = {
    parentAgent,
    agents: new Map([[parentAgent.id, parentAgent]]),
    events: [],
    eventInputs: [],
    stateUpdates: [],
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
    getSubagent(threadId, subagentId) {
      return this.surface.getSubagent(this, threadId, subagentId);
    },
    getRun(runId) {
      return this.runs.get(runId);
    },
    appendThreadSubagentControlEvent(input) {
      this.eventInputs.push(input);
      return this.surface.appendThreadSubagentControlEvent(this, input);
    },
    subagentProjection(record) {
      return this.surface.subagentProjection(record);
    },
  };
  return store;
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

function assertRuntimeSubagentControlRustCoreRequired(error, {
  operation,
  operationKind,
  threadId = "thread_1",
  subagentId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_subagent_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.subagent_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.thread_id, threadId);
  if (subagentId) assert.equal(error.details.subagent_id, subagentId);
  assert.equal(error.details.evidence_refs.includes("runtime_subagent_control_js_facade_retired"), true);
  assert.equal(error.details.evidence_refs.includes(`${operation}_js_facade_retired`), true);
  assert.equal(
    error.details.evidence_refs.includes("rust_daemon_core_runtime_subagent_control_required"),
    true,
  );
  assertNoOwnKeys(error.details, retiredSubagentErrorDetailAliasKeys);
  return true;
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

test("subagent lifecycle mutation facades fail closed before JS truth mutation", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;
  const baseline = {
    agents: store.agents.size,
    runs: store.runs.size,
    events: store.events.length,
    writes: store.writes.length,
    stateUpdates: store.stateUpdates.length,
  };

  const cases = [
    {
      operation: "runtime_subagent_spawn",
      operationKind: "subagent.spawn",
      call: () => surface.spawnSubagent(store, "thread_1", { prompt: "Plan the migration" }),
    },
    {
      operation: "runtime_subagent_wait",
      operationKind: "subagent.wait",
      subagentId: "subagent_1",
      call: () => surface.waitSubagent(store, "thread_1", "subagent_1"),
    },
    {
      operation: "runtime_subagent_input",
      operationKind: "subagent.input",
      subagentId: "subagent_1",
      call: () => surface.sendSubagentInput(store, "thread_1", "subagent_1", { input: "Follow up" }),
    },
    {
      operation: "runtime_subagent_resume",
      operationKind: "subagent.resume",
      subagentId: "subagent_1",
      call: () => surface.resumeSubagent(store, "thread_1", "subagent_1", { prompt: "Resume" }),
    },
    {
      operation: "runtime_subagent_assign",
      operationKind: "subagent.assign",
      subagentId: "subagent_1",
      call: () => surface.assignSubagent(store, "thread_1", "subagent_1", { role: "reviewer" }),
    },
    {
      operation: "runtime_subagent_cancel",
      operationKind: "subagent.cancel",
      subagentId: "subagent_1",
      call: () => surface.cancelSubagent(store, "thread_1", "subagent_1", { reason: "operator_cancel" }),
    },
    {
      operation: "runtime_subagent_cancel_propagation",
      operationKind: "subagent.cancel.propagate",
      call: () => surface.propagateSubagentCancellation(store, "thread_1", { reason: "parent_cancel" }),
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertRuntimeSubagentControlRustCoreRequired(error, testCase),
    );
  }

  assert.equal(store.agents.size, baseline.agents);
  assert.equal(store.runs.size, baseline.runs);
  assert.equal(store.events.length, baseline.events);
  assert.equal(store.writes.length, baseline.writes);
  assert.equal(store.stateUpdates.length, baseline.stateUpdates);
});

test("subagent control event append facade fails closed before JS runtime event append", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;

  assert.throws(
    () =>
      surface.appendThreadSubagentControlEvent(store, {
        threadId: "thread_1",
        parentAgent: store.parentAgent,
        record: {
          subagent_id: "subagent_1",
          agent_id: "agent_child_1",
          parent_thread_id: "thread_1",
          role: "reviewer",
          lifecycle_status: "running",
        },
        request: { source: "agent_studio" },
        operation: "cancel",
        status: "canceled",
      }),
    (error) =>
      assertRuntimeSubagentControlRustCoreRequired(error, {
        operation: "runtime_subagent_control_event",
        operationKind: "subagent.cancel",
        subagentId: "subagent_1",
      }),
  );

  assert.equal(store.events.length, 0);
});

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

test("subagent read projection facades fail closed before JS subagent/run reads", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();

  const baseline = {
    agents: store.agents.size,
    runs: store.runs.size,
    events: store.events.length,
    writes: store.writes.length,
    stateUpdates: store.stateUpdates.length,
  };
  const cases = [
    {
      operation: "runtime_subagent_list",
      operationKind: "subagent.list",
      call: () => surface.listSubagents(store, "thread_1", { role: "reviewer" }),
    },
    {
      operation: "runtime_subagent_get",
      operationKind: "subagent.get",
      subagentId: "subagent_1",
      call: () => surface.getSubagent(store, "thread_1", "subagent_1"),
    },
    {
      operation: "runtime_subagent_result",
      operationKind: "subagent.result",
      subagentId: "subagent_2",
      call: () => surface.getSubagentResult(store, "thread_1", "subagent_2"),
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertRuntimeSubagentControlRustCoreRequired(error, testCase),
    );
  }

  assert.equal(store.agents.size, baseline.agents);
  assert.equal(store.runs.size, baseline.runs);
  assert.equal(store.events.length, baseline.events);
  assert.equal(store.writes.length, baseline.writes);
  assert.equal(store.stateUpdates.length, baseline.stateUpdates);
});
