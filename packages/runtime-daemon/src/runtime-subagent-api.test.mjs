import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSubagentApi } from "./runtime-subagent-api.mjs";

function createLifecycleAgentForTest(state, options = {}) {
  const agentId = `agent_spawn_${state.agentCreates.length + 1}`;
  const agent = {
    id: agentId,
    cwd: options.local?.cwd ?? state.parentAgent.cwd,
    modelId: options.model?.id ?? "auto",
    requestedModelId: options.model?.id ?? "auto",
    modelRouteId: options.model?.route_id ?? "route.local-first",
  };
  state.agentCreates.push({ options, agent });
  state.agents.set(agentId, agent);
  return agent;
}

function createLifecycleRunForTest(state, agentId, request = {}) {
  const runId = `run_created_${state.runCreates.length + 1}`;
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
  state.runCreates.push({ agentId, request, run });
  state.runs.set(runId, run);
  return run;
}

function createStore() {
  const parentAgent = {
    id: "agent_parent",
    cwd: "/tmp/runtime-subagent-surface-test",
    modelId: "model-parent",
    requestedModelId: "model-parent",
    modelRouteId: "route.parent",
  };
  const store = {
    stateDir: "/runtime-state",
    parentAgent,
    agents: new Map([
      [parentAgent.id, parentAgent],
      ["agent_child_1", { id: "agent_child_1", cwd: parentAgent.cwd }],
      ["agent_child_2", { id: "agent_child_2", cwd: parentAgent.cwd }],
    ]),
    events: [],
    eventInputs: [],
    agentCreates: [],
    runCreates: [],
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
      if (agent.id !== parentAgent.id) {
        return {
          thread_id: `thread_${agent.id.replace(/^agent_/, "")}`,
          latest_turn_id: null,
        };
      }
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
    getAgent(agentId) {
      return this.agents.get(agentId);
    },
    appendThreadSubagentControlEvent(input) {
      this.eventInputs.push(input);
      return this.surface.appendThreadSubagentControlEvent(this, input);
    },
    appendRuntimeEvent(event) {
      const eventIdByKind = {
        "subagent.spawned": "event_subagent_spawn_1",
        "subagent.wait_completed": "event_subagent_wait_1",
        "subagent.input_sent": "event_subagent_input_1",
        "subagent.resumed": "event_subagent_resume_1",
        "subagent.assigned": "event_subagent_assign_1",
        "subagent.canceled": "event_subagent_cancel_1",
      };
      const admitted = {
        ...event,
        event_id: event.event_id ?? eventIdByKind[event.event_kind] ?? "event_subagent_control_1",
        created_at: event.created_at ?? "2026-06-04T12:00:04.000Z",
        receipt_refs: [...(event.receipt_refs ?? []), "receipt_event_admitted"],
      };
      this.events.push(admitted);
      return admitted;
    },
    writeSubagent(record, operationKind) {
      this.stateUpdates.push({ record, operationKind });
      this.subagents.set(record.subagent_id, record);
      return { record, operation_kind: operationKind };
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

function assertRuntimeSubagentProjectionMissing(error, {
  operation,
  operationKind,
  projectionKind,
  threadId = "thread_1",
  subagentId = null,
  role = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_subagent_read_projection_rust_projection_missing");
  assert.equal(error.details.rust_core_boundary, "runtime.subagent_projection");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.projection_kind, projectionKind);
  assert.equal(error.details.thread_id, threadId);
  if (subagentId) assert.equal(error.details.subagent_id, subagentId);
  if (role) assert.equal(error.details.role, role);
  assert.equal(error.details.evidence_refs.includes("runtime_subagent_read_projection_rust_owned"), true);
  assert.equal(error.details.evidence_refs.includes("runtime_subagent_read_projection_js_facade_retired"), true);
  assertNoOwnKeys(error.details, [
    ...retiredSubagentErrorDetailAliasKeys,
    "projectionKind",
    "rustCoreBoundary",
    "operationKind",
  ]);
  return true;
}

function assertRuntimeSubagentControlPlanningMissing(error, {
  operation,
  operationKind,
  threadId = "thread_1",
  subagentId = null,
  evidenceRefs = [],
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_subagent_control_rust_projection_missing");
  assert.equal(error.details.rust_core_boundary, "runtime.subagent_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.thread_id, threadId);
  if (subagentId) assert.equal(error.details.subagent_id, subagentId);
  for (const evidenceRef of evidenceRefs) {
    assert.equal(error.details.evidence_refs.includes(evidenceRef), true);
  }
  assertNoOwnKeys(error.details, [
    ...retiredSubagentErrorDetailAliasKeys,
    "rustCoreBoundary",
    "operationKind",
  ]);
  return true;
}

function projectSubagentForTest(request) {
  const projectionFixture = {
    subagents: [
      {
        subagent_id: "subagent_2",
        agent_id: "agent_child_2",
        run_id: "run_2",
        parent_thread_id: "thread_1",
        parent_turn_id: "turn_1",
        role: "reviewer",
        lifecycle_status: "completed",
        created_at: "2026-06-04T12:00:02.000Z",
      },
      {
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
      },
      {
        subagent_id: "subagent_other",
        parent_thread_id: "thread_other",
        role: "reviewer",
        lifecycle_status: "running",
        created_at: "2026-06-04T12:00:00.000Z",
      },
      {
        subagent_id: "subagent_worker",
        parent_thread_id: "thread_1",
        role: "worker",
        lifecycle_status: "running",
        created_at: "2026-06-04T12:00:03.000Z",
      },
    ],
    runs: [
      {
        id: "run_1",
        agentId: "agent_child_1",
        status: "completed",
        result: "Subagent one completed.",
        receipts: [{ id: "receipt_run_1" }],
      },
      {
        id: "run_2",
        agentId: "agent_child_2",
        status: "completed",
        result: "Subagent two completed.",
        receipts: [{ id: "receipt_run_2" }],
      },
    ],
  };
  const records = projectionFixture.subagents.filter(
    (record) =>
      record.parent_thread_id === request.thread_id &&
      (!request.role || record.role === request.role),
  );
  if (request.projection_kind === "list") {
    return {
      projection_kind: "list",
      projection: records.map((record) => ({
        ...record,
        schema_version: "ioi.runtime.subagent-manager.v1",
        object: "ioi.runtime_subagent",
      })),
    };
  }
  const record = records.find((candidate) => candidate.subagent_id === request.subagent_id) ?? null;
  if (request.projection_kind === "get") {
    return {
      projection_kind: "get",
      projection: record
        ? {
            ...record,
            schema_version: "ioi.runtime.subagent-manager.v1",
            object: "ioi.runtime_subagent",
          }
        : null,
    };
  }
  const run = projectionFixture.runs.find((candidate) => candidate.id === record?.run_id) ?? {};
  return {
    projection_kind: "result",
    projection: record
      ? {
          schema_version: "ioi.runtime.subagent-result.v1",
          object: "ioi.runtime_subagent_result",
          subagent_id: record.subagent_id,
          agent_id: record.agent_id ?? null,
          run_id: run.id ?? record.run_id,
          status: record.lifecycle_status,
          lifecycle_status: record.lifecycle_status,
          result: run.result ?? "",
          receipt_refs: [run.receipts?.[0]?.id].filter(Boolean),
        }
      : null,
  };
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

test("subagent lifecycle mutation facades stay retired before JS truth mutation", () => {
  const store = createStore();
  const surface = createRuntimeSubagentApi();
  store.surface = surface;
  const baseline = {
    agents: store.agents.size,
    runs: store.runs.size,
    agentCreates: store.agentCreates.length,
    runCreates: store.runCreates.length,
    events: store.events.length,
    writes: store.writes.length,
    stateUpdates: store.stateUpdates.length,
  };

  assert.throws(
    () => surface.propagateSubagentCancellation(store, "thread_1", { reason: "parent_cancel" }),
    (error) =>
      assertRuntimeSubagentControlPlanningMissing(error, {
        operation: "cancel",
        operationKind: "subagent.cancel.propagate",
        evidenceRefs: [
          "runtime_subagent_cancel_propagation_rust_owned",
          "runtime_subagent_cancel_control_rust_owned",
          "runtime_subagent_cancel_run_rust_owned",
        ],
      }),
  );

  assert.equal(store.agents.size, baseline.agents);
  assert.equal(store.runs.size, baseline.runs);
  assert.equal(store.agentCreates.length, baseline.agentCreates);
  assert.equal(store.runCreates.length, baseline.runCreates);
  assert.equal(store.events.length, baseline.events);
  assert.equal(store.writes.length, baseline.writes);
  assert.equal(store.stateUpdates.length, baseline.stateUpdates);
});

test("subagent direct controls fail closed before Rust read/control planning", () => {
  const store = createStore();
  const surface = createRuntimeSubagentApi();
  store.surface = surface;
  const baseline = {
    agents: store.agents.size,
    runs: store.runs.size,
    agentCreates: store.agentCreates.length,
    runCreates: store.runCreates.length,
    events: store.events.length,
    writes: store.writes.length,
    stateUpdates: store.stateUpdates.length,
  };

  assert.throws(
    () => surface.spawnSubagent(store, "thread_1", { prompt: "Plan the migration" }),
    (error) =>
      assertRuntimeSubagentControlPlanningMissing(error, {
        operation: "spawn",
        operationKind: "subagent.spawn",
        evidenceRefs: [
          "runtime_subagent_spawn_control_rust_owned",
          "runtime_subagent_agent_create_rust_owned",
          "runtime_subagent_run_create_rust_owned",
        ],
      }),
  );

  const cases = [
    {
      call: () => surface.sendSubagentInput(store, "thread_1", "subagent_1", { input: "Follow up" }),
      expected: {
        operation: "runtime_subagent_get",
        operationKind: "runtime.subagent_projection.get",
        projectionKind: "get",
        subagentId: "subagent_1",
      },
    },
    {
      call: () => surface.resumeSubagent(store, "thread_1", "subagent_1", { prompt: "Resume" }),
      expected: {
        operation: "runtime_subagent_get",
        operationKind: "runtime.subagent_projection.get",
        projectionKind: "get",
        subagentId: "subagent_1",
      },
    },
    {
      call: () => surface.waitSubagent(store, "thread_1", "subagent_1"),
      expected: {
        operation: "runtime_subagent_get",
        operationKind: "runtime.subagent_projection.get",
        projectionKind: "get",
        subagentId: "subagent_1",
      },
    },
    {
      call: () => surface.assignSubagent(store, "thread_1", "subagent_1", { role: "reviewer" }),
      expected: {
        operation: "runtime_subagent_get",
        operationKind: "runtime.subagent_projection.get",
        projectionKind: "get",
        subagentId: "subagent_1",
      },
    },
    {
      call: () => surface.cancelSubagent(store, "thread_1", "subagent_1", { reason: "operator_cancel" }),
      expected: {
        operation: "runtime_subagent_get",
        operationKind: "runtime.subagent_projection.get",
        projectionKind: "get",
        subagentId: "subagent_1",
      },
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertRuntimeSubagentProjectionMissing(error, testCase.expected),
    );
  }

  assert.equal(store.agents.size, baseline.agents);
  assert.equal(store.runs.size, baseline.runs);
  assert.equal(store.agentCreates.length, baseline.agentCreates);
  assert.equal(store.runCreates.length, baseline.runCreates);
  assert.equal(store.events.length, baseline.events);
  assert.equal(store.writes.length, baseline.writes);
  assert.equal(store.stateUpdates.length, baseline.stateUpdates);
});

test("subagent control event append fails closed before JS runtime event append without Rust planning", () => {
  const store = createStore();
  const surface = createRuntimeSubagentApi();
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
      assertRuntimeSubagentControlPlanningMissing(error, {
        operation: "cancel",
        operationKind: "subagent.cancel",
        subagentId: "subagent_1",
        evidenceRefs: [
          "runtime_subagent_cancel_control_rust_owned",
          "runtime_subagent_control_event_rust_owned",
        ],
      }),
  );

  assert.equal(store.events.length, 0);
  assert.equal(store.stateUpdates.length, 0);
});

test("subagent control event append uses Rust control planning and Agentgres event admission", () => {
  const controlCalls = [];
  const stateUpdateCalls = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    contextPolicyCore: {
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        assert.equal(request.operation, "cancel");
        assert.equal(request.operation_kind, "subagent.cancel");
        assert.equal(request.thread_id, "thread_1");
        assert.equal(request.subagent.subagent_id, "subagent_1");
        return {
          operation: "cancel",
          operation_kind: "subagent.cancel",
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: "turn_latest",
            item_id: "turn_latest:item:subagent:cancel:subagent_1",
            idempotency_key: "thread:thread_1:subagent.cancel:subagent_1:test",
            source: "agent_studio",
            source_event_kind: "OperatorControl.SubagentCancel",
            event_kind: "subagent.canceled",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation: "cancel", subagent_id: "subagent_1" },
            receipt_refs: ["receipt_direct_cancel"],
            policy_decision_refs: ["policy_direct_cancel"],
          },
          evidence_refs: ["runtime_subagent_control_event_rust_owned"],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        throw new Error("direct control-event append must not update subagent record");
      },
    },
    createLifecycleAgent: createLifecycleAgentForTest,
    createLifecycleRun: createLifecycleRunForTest,
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const event = surface.appendThreadSubagentControlEvent(store, {
    threadId: "thread_1",
    parentAgent: store.parentAgent,
    record: {
      subagent_id: "subagent_1",
      agent_id: "agent_child_1",
      parent_thread_id: "thread_1",
      parent_turn_id: "turn_latest",
      role: "reviewer",
      lifecycle_status: "running",
      updated_at: "2026-06-04T12:00:01.000Z",
    },
    request: { source: "agent_studio" },
    operation: "cancel",
    status: "canceled",
  });

  assert.equal(controlCalls.length, 1);
  assert.equal(controlCalls[0].event_stream_id, "thread_1:events");
  assert.equal(controlCalls[0].event_seed, "2026-06-04T12:00:01.000Z");
  assert.equal(controlCalls[0].evidence_refs.includes("runtime_subagent_control_event_rust_owned"), true);
  assert.equal(event.event_id, "event_subagent_cancel_1");
  assert.equal(event.event_kind, "subagent.canceled");
  assert.equal(event.thread_id, "thread_1");
  assert.equal(event.payload.subagent_id, "subagent_1");
  assert.deepEqual(event.receipt_refs, ["receipt_direct_cancel", "receipt_event_admitted"]);
  assert.equal(store.events.length, 1);
  assert.equal(store.events[0], event);
  assert.equal(store.stateUpdates.length, 0);
  assert.equal(store.writes.length, 0);
  assert.equal(stateUpdateCalls.length, 0);
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

test("subagent read projections fail closed before JS subagent/run reads without Rust", () => {
  const store = createStore();
  const surface = createRuntimeSubagentApi();

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
      operationKind: "runtime.subagent_projection.list",
      projectionKind: "list",
      role: "reviewer",
      call: () => surface.listSubagents(store, "thread_1", { role: "reviewer" }),
    },
    {
      operation: "runtime_subagent_get",
      operationKind: "runtime.subagent_projection.get",
      projectionKind: "get",
      subagentId: "subagent_1",
      call: () => surface.getSubagent(store, "thread_1", "subagent_1"),
    },
    {
      operation: "runtime_subagent_result",
      operationKind: "runtime.subagent_projection.result",
      projectionKind: "result",
      subagentId: "subagent_2",
      call: () => surface.getSubagentResult(store, "thread_1", "subagent_2"),
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertRuntimeSubagentProjectionMissing(error, testCase),
    );
  }

  assert.equal(store.agents.size, baseline.agents);
  assert.equal(store.runs.size, baseline.runs);
  assert.equal(store.events.length, baseline.events);
  assert.equal(store.writes.length, baseline.writes);
  assert.equal(store.stateUpdates.length, baseline.stateUpdates);
});

test("subagent read projections return Rust daemon-core projections", () => {
  const projectionCalls = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    contextPolicyCore: {
      projectRuntimeSubagentProjection(request) {
        projectionCalls.push(request);
        return projectSubagentForTest(request);
      },
    },
  });

  assert.deepEqual(
    surface.listSubagents(store, "thread_1", { role: "reviewer" }).map((record) => record.subagent_id),
    ["subagent_2", "subagent_1"],
  );
  assert.equal(surface.getSubagent(store, "thread_1", "subagent_1").object, "ioi.runtime_subagent");
  assert.deepEqual(surface.getSubagentResult(store, "thread_1", "subagent_2"), {
    schema_version: "ioi.runtime.subagent-result.v1",
    object: "ioi.runtime_subagent_result",
    subagent_id: "subagent_2",
    agent_id: "agent_child_2",
    run_id: "run_2",
    status: "completed",
    lifecycle_status: "completed",
    result: "Subagent two completed.",
    receipt_refs: ["receipt_run_2"],
  });
  assert.deepEqual(
    projectionCalls.map((request) => request.operation),
    ["runtime_subagent_projection", "runtime_subagent_projection", "runtime_subagent_projection"],
  );
  assert.deepEqual(
    projectionCalls.map((request) => request.projection_kind),
    ["list", "get", "result"],
  );
  assert.equal(projectionCalls[0].thread_id, "thread_1");
  assert.equal(projectionCalls[0].role, "reviewer");
  assert.equal(projectionCalls[1].subagent_id, "subagent_1");
  assert.equal(projectionCalls[2].subagent_id, "subagent_2");
  assert.equal(projectionCalls.every((request) => request.state_dir === "/runtime-state"), true);
  assert.equal(projectionCalls.every((request) => Object.hasOwn(request, "projection") === false), true);
  assert.equal(
    projectionCalls[0].evidence_refs.includes("runtime_subagent_read_projection_js_facade_retired"),
    true,
  );
});

test("subagent spawn control uses Rust agent and run creation, control planning, state planning, and Agentgres commits", () => {
  const controlCalls = [];
  const stateUpdateCalls = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    contextPolicyCore: {
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        assert.equal(request.operation, "spawn");
        assert.equal(request.operation_kind, "subagent.spawn");
        assert.equal(request.subagent.subagent_id, "agent_spawn_1");
        assert.equal(request.subagent.agent_id, "agent_spawn_1");
        assert.equal(request.subagent.child_thread_id, "thread_spawn_1");
        assert.equal(request.subagent.parent_thread_id, "thread_1");
        return {
          operation: "spawn",
          operation_kind: "subagent.spawn",
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: request.subagent.parent_turn_id,
            item_id: "turn_latest:item:subagent:spawn:agent_spawn_1",
            idempotency_key: "thread:thread_1:subagent.spawn:agent_spawn_1:test",
            source: "agent_studio",
            source_event_kind: "OperatorControl.SubagentSpawn",
            event_kind: "subagent.spawned",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation: "spawn", subagent_id: "agent_spawn_1" },
            receipt_refs: ["receipt_spawn_control"],
            policy_decision_refs: ["policy_spawn_control"],
          },
          evidence_refs: ["runtime_subagent_spawn_control_rust_owned"],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        assert.equal(request.operation_kind, "subagent.spawn");
        assert.equal(request.subagent.event_id, "event_subagent_spawn_1");
        return {
          operation_kind: "subagent.spawn",
          subagent: {
            ...request.subagent,
            planned_by: "rust_subagent.spawn",
          },
        };
      },
    },
    createLifecycleAgent: createLifecycleAgentForTest,
    createLifecycleRun: createLifecycleRunForTest,
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const result = surface.spawnSubagent(store, "thread_1", {
    prompt: "Plan the migration",
    role: "reviewer",
    model_route_id: "route.spawn",
    tool_pack: "analysis-tools",
    output_contract: ["SUMMARY"],
    workflow_graph_id: "workflow_spawn",
    workflow_node_id: "node_spawn",
    receipt_refs: ["receipt_request"],
    policy_decision_refs: ["policy_request"],
  });

  assert.equal(Object.hasOwn(store, "createAgent"), false);
  assert.equal(Object.hasOwn(store, "createRun"), false);
  assert.equal(store.agentCreates.length, 1);
  assert.equal(store.agentCreates[0].options.model.route_id, "route.spawn");
  assert.equal(store.runCreates.length, 1);
  assert.equal(store.runCreates[0].agentId, "agent_spawn_1");
  assert.equal(store.runCreates[0].request.prompt, "Plan the migration");
  assert.equal(store.runCreates[0].request.options.receiver, "reviewer");
  assert.equal(store.runCreates[0].request.options.model.route_id, "route.spawn");
  assert.equal(controlCalls.length, 1);
  assert.equal(stateUpdateCalls.length, 1);
  assert.equal(store.events.length, 1);
  assert.equal(store.stateUpdates.length, 1);
  assert.equal(store.stateUpdates[0].operationKind, "subagent.spawn");
  assert.equal(result.subagent_id, "agent_spawn_1");
  assert.equal(result.child_thread_id, "thread_spawn_1");
  assert.equal(result.event.event_id, "event_subagent_spawn_1");
  assert.equal(result.result.run_id, "run_created_1");
  assert.equal(result.planned_by, "rust_subagent.spawn");
  assert.equal(store.subagents.get("agent_spawn_1").planned_by, "rust_subagent.spawn");
});

test("subagent wait control uses Rust control, state planning, and Agentgres commits", () => {
  const projectionCalls = [];
  const controlCalls = [];
  const stateUpdateCalls = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    contextPolicyCore: {
      projectRuntimeSubagentProjection(request) {
        projectionCalls.push(request);
        return projectSubagentForTest(request);
      },
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        assert.equal(request.operation_kind, "subagent.wait");
        assert.equal(request.subagent.subagent_id, "subagent_1");
        return {
          operation: "wait",
          operation_kind: "subagent.wait",
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: request.subagent.parent_turn_id,
            item_id: "turn_1:item:subagent:wait:subagent_1",
            idempotency_key: "thread:thread_1:subagent.wait:subagent_1:test",
            source: "agent_studio",
            source_event_kind: "OperatorControl.SubagentWait",
            event_kind: "subagent.wait_completed",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation: "wait", subagent_id: "subagent_1" },
            receipt_refs: ["receipt_wait_control"],
            policy_decision_refs: ["policy_wait_control"],
          },
          evidence_refs: ["runtime_subagent_wait_control_rust_owned"],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        assert.equal(request.operation_kind, "subagent.wait");
        assert.equal(request.subagent.wait_event_id, "event_subagent_wait_1");
        return {
          operation_kind: "subagent.wait",
          subagent: {
            ...request.subagent,
            planned_by: "rust_subagent_record_state_update",
          },
        };
      },
    },
    createLifecycleRun: createLifecycleRunForTest,
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const result = surface.waitSubagent(store, "thread_1", "subagent_1");

  assert.equal(projectionCalls.length, 1);
  assert.equal(controlCalls.length, 1);
  assert.equal(stateUpdateCalls.length, 1);
  assert.equal(store.events.length, 1);
  assert.equal(store.stateUpdates.length, 1);
  assert.equal(store.stateUpdates[0].operationKind, "subagent.wait");
  assert.equal(store.subagents.get("subagent_1").planned_by, "rust_subagent_record_state_update");
  assert.equal(result.subagent.wait_event_id, "event_subagent_wait_1");
  assert.deepEqual(result.receipt_refs, ["receipt_wait_control", "receipt_event_admitted"]);
});

test("subagent input and resume controls use Rust run creation, control planning, state planning, and Agentgres commits", () => {
  const projectionCalls = [];
  const controlCalls = [];
  const stateUpdateCalls = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    contextPolicyCore: {
      projectRuntimeSubagentProjection(request) {
        projectionCalls.push(request);
        return projectSubagentForTest(request);
      },
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        const operation = request.operation;
        return {
          operation,
          operation_kind: request.operation_kind,
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: request.subagent.parent_turn_id,
            item_id: `turn_1:item:subagent:${operation}:subagent_1`,
            idempotency_key: `thread:thread_1:subagent.${operation}:subagent_1:test`,
            source: "agent_studio",
            source_event_kind:
              operation === "send_input"
                ? "OperatorControl.SubagentSendInput"
                : "OperatorControl.SubagentResume",
            event_kind:
              operation === "send_input" ? "subagent.input_sent" : "subagent.resumed",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation, subagent_id: "subagent_1" },
            receipt_refs: [`receipt_${operation}_control`],
            policy_decision_refs: [`policy_${operation}_control`],
          },
          evidence_refs: [`runtime_subagent_${operation}_control_rust_owned`],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        return {
          operation_kind: request.operation_kind,
          subagent: {
            ...request.subagent,
            planned_by: `rust_${request.operation_kind}`,
          },
        };
      },
    },
    createLifecycleRun: createLifecycleRunForTest,
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const input = surface.sendSubagentInput(store, "thread_1", "subagent_1", {
    input: "Follow up",
  });
  const resumed = surface.resumeSubagent(store, "thread_1", "subagent_1", {
    prompt: "Resume now",
    model_route_id: "route.resume",
  });

  assert.deepEqual(
    projectionCalls.map((request) => request.operation_kind),
    [
      "runtime.subagent_projection.get",
      "runtime.subagent_projection.get",
    ],
  );
  assert.deepEqual(
    store.runCreates.map((call) => call.agentId),
    ["agent_child_1", "agent_child_1"],
  );
  assert.equal(store.runCreates[0].request.prompt, "Follow up");
  assert.equal(store.runCreates[0].request.options.receiver, "reviewer");
  assert.equal(store.runCreates[1].request.prompt, "Resume now");
  assert.equal(store.runCreates[1].request.options.model.route_id, "route.resume");
  assert.deepEqual(
    controlCalls.map((request) => request.operation_kind),
    ["subagent.input", "subagent.resume"],
  );
  assert.deepEqual(
    controlCalls.map((request) => request.operation),
    ["send_input", "resume"],
  );
  assert.deepEqual(
    stateUpdateCalls.map((request) => request.operation_kind),
    ["subagent.input", "subagent.resume"],
  );
  assert.deepEqual(
    store.stateUpdates.map((write) => write.operationKind),
    ["subagent.input", "subagent.resume"],
  );
  assert.equal(store.events.length, 2);
  assert.equal(input.input.input_id, "subagent_input_thread_1_subagent_1_2026-06-04T12_00_03_000Z");
  assert.equal(input.run_id, "run_created_1");
  assert.equal(input.input_event_id, "event_subagent_input_1");
  assert.equal(input.planned_by, "rust_subagent.input");
  assert.equal(resumed.resume.resume_id, "subagent_resume_thread_1_subagent_1_2026-06-04T12_00_03_000Z");
  assert.equal(resumed.subagent.run_id, "run_created_2");
  assert.equal(resumed.subagent.resume_event_id, "event_subagent_resume_1");
  assert.equal(resumed.subagent.planned_by, "rust_subagent.resume");
});

test("subagent assign and cancel controls use Rust control, state planning, and Agentgres commits", () => {
  const projectionCalls = [];
  const controlCalls = [];
  const stateUpdateCalls = [];
  const canceledRuns = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    cancelRun(state, runId, deps = {}) {
      assert.equal(typeof deps.contextPolicyCore?.planRuntimeSubagentControl, "function");
      canceledRuns.push(runId);
      const current = state.getRun(runId);
      const canceled = {
        ...current,
        status: "canceled",
        result: current.result ?? "",
        receipts: [...(current.receipts ?? []), { id: "receipt_run_cancel" }],
        updatedAt: "2026-06-04T12:00:05.000Z",
      };
      state.runs.set(runId, canceled);
      return canceled;
    },
    contextPolicyCore: {
      projectRuntimeSubagentProjection(request) {
        projectionCalls.push(request);
        return projectSubagentForTest(request);
      },
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        const operation = request.operation;
        return {
          operation,
          operation_kind: request.operation_kind,
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: request.subagent.parent_turn_id,
            item_id: `turn_1:item:subagent:${operation}:subagent_1`,
            idempotency_key: `thread:thread_1:subagent.${operation}:subagent_1:test`,
            source: "agent_studio",
            source_event_kind:
              operation === "assign"
                ? "OperatorControl.SubagentAssign"
                : "OperatorControl.SubagentCancel",
            event_kind:
              operation === "assign" ? "subagent.assigned" : "subagent.canceled",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation, subagent_id: "subagent_1" },
            receipt_refs: [`receipt_${operation}_control`],
            policy_decision_refs: [`policy_${operation}_control`],
          },
          evidence_refs: [`runtime_subagent_${operation}_control_rust_owned`],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        return {
          operation_kind: request.operation_kind,
          subagent: {
            ...request.subagent,
            planned_by: `rust_${request.operation_kind}`,
          },
        };
      },
    },
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const assigned = surface.assignSubagent(store, "thread_1", "subagent_1", {
    role: "architect",
    target_agent_id: "agent_child_1",
    tool_pack: "analysis-tools",
    model_route_id: "route.assign",
    merge_policy: "manual",
    cancellation_inheritance: "isolated",
  });
  const canceled = surface.cancelSubagent(store, "thread_1", "subagent_1", {
    reason: "operator_cancel",
  });

  assert.deepEqual(
    controlCalls.map((request) => request.operation_kind),
    ["subagent.assign", "subagent.cancel"],
  );
  assert.deepEqual(
    stateUpdateCalls.map((request) => request.operation_kind),
    ["subagent.assign", "subagent.cancel"],
  );
  assert.deepEqual(canceledRuns, ["run_1"]);
  assert.equal(store.events.length, 2);
  assert.deepEqual(
    store.stateUpdates.map((write) => write.operationKind),
    ["subagent.assign", "subagent.cancel"],
  );
  assert.equal(assigned.assignment.assignment_id.startsWith("subagent_assignment_"), true);
  assert.equal(assigned.subagent_id, "subagent_1");
  assert.equal(assigned.assignment.role, "architect");
  assert.equal(assigned.event.event_id, "event_subagent_assign_1");
  assert.equal(canceled.subagent.cancel_event_id, "event_subagent_cancel_1");
  assert.equal(canceled.subagent.lifecycle_status, "canceled");
  assert.equal(canceled.cancellation.reason, "operator_cancel");
  assert.equal(store.subagents.get("subagent_1").planned_by, "rust_subagent.cancel");
  assert.equal(projectionCalls.length, 2);
});

test("subagent cancellation propagation uses Rust projection, propagated cancel planning, state planning, and Agentgres commits", () => {
  const projectionCalls = [];
  const controlCalls = [];
  const stateUpdateCalls = [];
  const canceledRuns = [];
  const store = createStore();
  const surface = createRuntimeSubagentApi({
    cancelRun(state, runId, deps = {}) {
      assert.equal(typeof deps.contextPolicyCore?.planRuntimeSubagentControl, "function");
      canceledRuns.push(runId);
      const current = state.getRun(runId);
      const canceled = {
        ...current,
        status: "canceled",
        result: current.result ?? "",
        receipts: [...(current.receipts ?? []), { id: "receipt_run_propagated_cancel" }],
        updatedAt: "2026-06-04T12:00:05.000Z",
      };
      state.runs.set(runId, canceled);
      return canceled;
    },
    contextPolicyCore: {
      projectRuntimeSubagentProjection(request) {
        projectionCalls.push(request);
        return projectSubagentForTest(request);
      },
      planRuntimeSubagentControl(request) {
        controlCalls.push(request);
        assert.equal(request.operation, "cancel");
        assert.equal(request.operation_kind, "subagent.cancel.propagate");
        assert.equal(request.subagent.subagent_id, "subagent_1");
        assert.equal(request.subagent.cancellation_inherited, true);
        assert.equal(request.subagent.propagated_from_thread_id, "thread_1");
        return {
          operation: "cancel",
          operation_kind: "subagent.cancel.propagate",
          thread_id: request.thread_id,
          subagent_id: request.subagent.subagent_id,
          control_status: request.status,
          event: {
            event_stream_id: request.event_stream_id,
            thread_id: request.thread_id,
            turn_id: request.subagent.parent_turn_id,
            item_id: "turn_1:item:subagent:cancel:subagent_1",
            idempotency_key: "thread:thread_1:subagent.cancel.propagate:subagent_1:test",
            source: "agent_studio",
            source_event_kind: "OperatorControl.SubagentCancel",
            event_kind: "subagent.canceled",
            status: request.status,
            component_kind: "subagent_lifecycle",
            payload_schema_version: "ioi.runtime.subagent-manager.v1",
            payload: { operation: "cancel", subagent_id: "subagent_1" },
            receipt_refs: ["receipt_propagated_cancel_control"],
            policy_decision_refs: ["policy_propagated_cancel_control"],
          },
          evidence_refs: ["runtime_subagent_cancel_propagation_rust_owned"],
        };
      },
      planSubagentRecordStateUpdate(request) {
        stateUpdateCalls.push(request);
        assert.equal(request.operation_kind, "subagent.cancel.propagate");
        assert.equal(request.subagent.cancel_event_id, "event_subagent_cancel_1");
        return {
          operation_kind: "subagent.cancel.propagate",
          subagent: {
            ...request.subagent,
            planned_by: "rust_subagent.cancel.propagate",
          },
        };
      },
    },
    nowIso: () => "2026-06-04T12:00:03.000Z",
  });
  store.surface = surface;

  const result = surface.propagateSubagentCancellation(store, "thread_1", {
    reason: "parent_cancel",
  });

  assert.deepEqual(
    projectionCalls.map((request) => request.projection_kind),
    ["list", "get"],
  );
  assert.deepEqual(canceledRuns, ["run_1"]);
  assert.deepEqual(
    controlCalls.map((request) => request.operation_kind),
    ["subagent.cancel.propagate"],
  );
  assert.deepEqual(
    stateUpdateCalls.map((request) => request.operation_kind),
    ["subagent.cancel.propagate"],
  );
  assert.deepEqual(
    store.stateUpdates.map((write) => write.operationKind),
    ["subagent.cancel.propagate"],
  );
  assert.equal(store.events.length, 1);
  assert.equal(result.object, "ioi.runtime_subagent_cancellation_propagation");
  assert.equal(result.status, "propagated");
  assert.equal(result.thread_id, "thread_1");
  assert.equal(result.parent_agent_id, "agent_parent");
  assert.equal(result.reason, "parent_cancel");
  assert.equal(result.candidate_count, 3);
  assert.equal(result.canceled_count, 1);
  assert.equal(result.skipped_count, 2);
  assert.deepEqual(result.event_refs, ["event_subagent_cancel_1"]);
  assert.equal(result.receipt_refs.includes("receipt_event_admitted"), true);
  assert.equal(result.canceled_subagents[0].subagent_id, "subagent_1");
  assert.equal(result.canceled_subagents[0].planned_by, "rust_subagent.cancel.propagate");
  assert.equal(result.canceled_subagents[0].cancellation_inherited, true);
  assert.equal(result.canceled_subagents[0].propagated_from_thread_id, "thread_1");
  assert.deepEqual(
    result.skipped_subagents.map((record) => record.subagent_id),
    ["subagent_2", "subagent_worker"],
  );
});
