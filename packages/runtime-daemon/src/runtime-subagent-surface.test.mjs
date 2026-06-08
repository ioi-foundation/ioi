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

test("subagent surface lists, filters, and projects thread subagents", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();

  const listed = surface.listSubagents(store, "thread_1", { role: "reviewer" });
  const canonicalAliasListed = surface.listSubagents(store, "thread_1", {
    role: "reviewer",
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
    ["subagent_1", "subagent_2"],
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

test("subagent result reads ignore retired camelCase record aliases", () => {
  const store = createStore();
  const surface = createRuntimeSubagentSurface();
  store.surface = surface;
  store.subagents.set("subagent_2", {
    ...store.subagents.get("subagent_2"),
    output_contract: ["SUMMARY"],
    runId: "run_1",
    outputContract: ["MISSING_SECTION"],
  });

  const read = surface.getSubagentResult(store, "thread_1", "subagent_2");

  assert.equal(read.result, "Subagent two completed.");
  assert.equal(read.output_contract_status, "passed");
  assert.equal(read.subagent.output_contract_status, "passed");
  assertCanonicalSubagentRecordOutput(read.subagent);
});
