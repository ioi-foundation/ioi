import assert from "node:assert/strict";
import test from "node:test";

import { JOB_TERMINAL_EVENT_TYPES, TERMINAL_EVENT_TYPES } from "./runtime-contract-constants.mjs";
import { cancelRun } from "./runtime-run-cancellation.mjs";
import { createRuntimeRunHelpers } from "./runtime-run-helpers.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

const runHelpers = createRuntimeRunHelpers({ normalizeArray });

function runtimeTaskRecord({ runId, agent, prompt, mode, taskFamily, selectedStrategy, status, createdAt, updatedAt }) {
  return {
    taskId: `task_${runId}`,
    runId,
    agentId: agent.id,
    prompt,
    mode,
    taskFamily,
    selectedStrategy,
    status,
    summary: `Runtime task ${status}`,
    createdAt,
    updatedAt,
  };
}

function runtimeJobRecord({
  runtimeTask,
  status,
  lifecycle,
  eventCount,
  terminalEventCount,
  artifactNames,
  receiptKinds,
  createdAt,
  updatedAt,
}) {
  return {
    jobId: `job_${runtimeTask.runId}`,
    runtimeTaskId: runtimeTask.taskId,
    status,
    lifecycleStatus: status,
    lifecycle,
    eventCount,
    terminalEventCount,
    artifactNames,
    receiptKinds,
    createdAt,
    updatedAt,
  };
}

function runtimeChecklistRecord({ runtimeTask, runtimeJob, status, createdAt, updatedAt }) {
  return {
    checklistId: `checklist_${runtimeTask.runId}`,
    runtimeTaskId: runtimeTask.taskId,
    runtimeJobId: runtimeJob.jobId,
    status,
    summary: `Runtime checklist ${status}`,
    createdAt,
    updatedAt,
  };
}

function attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist) {
  return {
    ...runtimeJob,
    checklistId: runtimeChecklist.checklistId,
  };
}

function artifact(runId, name, mediaType, receiptId, content, redaction) {
  return {
    artifactId: `artifact_${runId}_${name}`,
    name,
    mediaType,
    receiptId,
    content,
    redaction,
  };
}

function deps(calls = [], stateUpdate = null) {
  return {
    now: () => "2026-06-06T04:45:00.000Z",
    contextPolicyRunner: {
      planRunCancelStateUpdate(request = {}) {
        calls.push({ operation: "plan_run_cancel_state_update", input: request });
        return stateUpdate ?? {
          status: "planned",
          operation_kind: "run.cancel",
          run: plannedCancellationRun(request.run, request.canceled_at),
        };
      },
    },
  };
}

function plannedCancellationRun(run, canceledAt) {
  const nonTerminalEvents = normalizeArray(run.events).filter(
    (event) => !TERMINAL_EVENT_TYPES.has(event.type) && !JOB_TERMINAL_EVENT_TYPES.has(event.type),
  );
  const hasRuntimeTaskEvent = nonTerminalEvents.some((event) => event.type === "runtime_task");
  const hasRuntimeChecklistEvent = nonTerminalEvents.some((event) => event.type === "runtime_checklist");
  const finalEventCount =
    nonTerminalEvents.length + (hasRuntimeTaskEvent ? 0 : 1) + (hasRuntimeChecklistEvent ? 0 : 1) + 2;
  const runtimeTask = runtimeTaskRecord({
    runId: run.id,
    agent: { id: run.agentId },
    prompt: run.objective,
    mode: run.mode,
    taskFamily: run.trace?.qualityLedger?.taskFamily ?? runHelpers.taskFamilyForMode(run.mode ?? "send"),
    selectedStrategy: run.trace?.qualityLedger?.selectedStrategy ?? runHelpers.strategyForMode(run.mode ?? "send"),
    createdAt: run.createdAt,
    updatedAt: canceledAt,
    status: "canceled",
  });
  let runtimeJob = runtimeJobRecord({
    runtimeTask,
    status: "canceled",
    createdAt: run.createdAt,
    updatedAt: canceledAt,
    queuedAt: run.runtimeJob?.queuedAt ?? run.createdAt,
    startedAt: run.runtimeJob?.startedAt ?? run.createdAt,
    completedAt: canceledAt,
    lifecycle: ["queued", "started", "canceled"],
    eventCount: finalEventCount,
    terminalEventCount: 1,
    artifactNames: normalizeArray(run.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
    receiptKinds: normalizeArray(run.receipts).map((receipt) => receipt.kind).filter(Boolean),
  });
  const runtimeChecklist = runtimeChecklistRecord({
    runtimeTask,
    runtimeJob,
    status: "canceled",
    createdAt: run.createdAt,
    updatedAt: canceledAt,
  });
  runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
  const canceledEvents = nonTerminalEvents.map((event) => {
    if (event.type === "runtime_task") {
      return {
        ...event,
        data: {
          ...runtimeTask,
          receiptId: `receipt_${run.id}_runtime_task`,
          eventKind: "RuntimeTaskRecord",
          workflowNodeId: "runtime.runtime-task",
        },
      };
    }
    return event;
  });
  if (!hasRuntimeTaskEvent) {
    canceledEvents.push(
      runHelpers.makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_task", "Runtime task record written", {
        ...runtimeTask,
        receiptId: `receipt_${run.id}_runtime_task`,
        eventKind: "RuntimeTaskRecord",
        workflowNodeId: "runtime.runtime-task",
      }),
    );
  }
  if (!hasRuntimeChecklistEvent) {
    canceledEvents.push(
      runHelpers.makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_checklist", "Runtime checklist recorded", {
        ...runtimeChecklist,
        receiptId: `receipt_${run.id}_runtime_checklist`,
        eventKind: "RuntimeChecklistRecord",
        workflowNodeId: "runtime.runtime-checklist",
      }),
    );
  }
  canceledEvents.push(
    runHelpers.makeEvent(run.id, run.agentId, canceledEvents.length, "job_canceled", "Runtime job canceled", {
      ...runtimeJob,
      lifecycleStatus: "canceled",
      receiptId: `receipt_${run.id}_runtime_job`,
      eventKind: "JobCanceled",
      workflowNodeId: "runtime.runtime-job",
    }),
  );
  canceledEvents.push(
    runHelpers.makeEvent(run.id, run.agentId, canceledEvents.length, "canceled", "Run canceled", {
      reason: "operator_cancel",
      priorStatus: run.status,
    }),
  );
  const runtimeChecklistReceipt = {
    id: `receipt_${run.id}_runtime_checklist`,
    kind: "runtime_checklist",
    summary: runtimeChecklist.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeChecklist.checklistId,
      runtimeTask.taskId,
      runtimeJob.jobId,
      "RuntimeChecklistNode",
      "runtime.checklists.durable_projection",
    ].filter(Boolean),
  };
  const receipts = [...normalizeArray(run.receipts), runtimeChecklistReceipt];
  const artifacts = normalizeArray(run.artifacts).map((item) => {
    if (item.name === "runtime-task.json") return { ...item, content: runtimeTask };
    if (item.name === "runtime-job.json") return { ...item, content: runtimeJob };
    if (item.name === "runtime-checklist.json") return { ...item, content: runtimeChecklist };
    return item;
  });
  if (!artifacts.some((item) => item.name === "runtime-checklist.json")) {
    artifacts.push(
      artifact(
        run.id,
        "runtime-checklist.json",
        "application/json",
        runtimeChecklistReceipt.id,
        runtimeChecklist,
        "redacted",
      ),
    );
  }
  const trace = {
    ...run.trace,
    events: canceledEvents,
    receipts,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    stopCondition: {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale:
        "Cancellation became the single terminal event and replay cursor continuity was preserved.",
    },
    qualityLedger: {
      ...run.trace.qualityLedger,
      failureOntologyLabels: [
        ...new Set([...(run.trace.qualityLedger?.failureOntologyLabels ?? []), "operator_cancel"]),
      ],
    },
  };
  return {
    ...run,
    status: "canceled",
    updatedAt: canceledAt,
    events: canceledEvents,
    trace,
    receipts,
    artifacts,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    result: "Run canceled with terminal event continuity preserved.",
  };
}

function fakeState(run) {
  const writes = [];
  return {
    runs: new Map([[run.id, run]]),
    writes,
    getRun(runId) {
      return this.runs.get(runId);
    },
    writeRun(updated, operation) {
      writes.push({ operation, run: updated });
    },
  };
}

test("cancelRun rewrites terminal continuity and durable runtime projections", () => {
  const run = {
    id: "run_cancel_one",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel this run",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    runtimeJob: {
      queuedAt: "2026-06-04T00:00:00.000Z",
      startedAt: "2026-06-04T00:00:00.500Z",
    },
    events: [
      {
        id: "run_cancel_one:event:000:runtime_task",
        type: "runtime_task",
        data: { status: "running", receiptId: "old_task_receipt" },
      },
      {
        id: "run_cancel_one:event:001:delta",
        type: "delta",
        data: { text: "partial" },
      },
      {
        id: "run_cancel_one:event:002:job_completed",
        type: "job_completed",
        data: { status: "completed" },
      },
      {
        id: "run_cancel_one:event:003:completed",
        type: "completed",
        data: { status: "completed" },
      },
    ],
    trace: {
      events: [],
      receipts: [],
      qualityLedger: {
        failureOntologyLabels: ["existing_label"],
      },
    },
    receipts: [{ id: "receipt_existing", kind: "existing" }],
    artifacts: [
      {
        name: "runtime-task.json",
        content: { status: "running" },
      },
    ],
  };
  const state = fakeState(run);
  const calls = [];

  const updated = cancelRun(state, run.id, deps(calls));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].operation, "plan_run_cancel_state_update");
  assert.equal(calls[0].input.run_id, run.id);
  assert.equal(calls[0].input.canceled_at, "2026-06-06T04:45:00.000Z");
  assert.equal(updated.status, "canceled");
  assert.equal(updated.result, "Run canceled with terminal event continuity preserved.");
  assert.deepEqual(updated.events.map((event) => event.type), [
    "runtime_task",
    "delta",
    "runtime_checklist",
    "job_canceled",
    "canceled",
  ]);
  assert.equal(updated.events.filter((event) => TERMINAL_EVENT_TYPES.has(event.type)).length, 1);
  assert.equal(updated.events.filter((event) => JOB_TERMINAL_EVENT_TYPES.has(event.type)).length, 1);
  assert.equal(updated.events[0].data.status, "canceled");
  assert.equal(updated.runtimeTask.status, "canceled");
  assert.equal(updated.runtimeJob.status, "canceled");
  assert.equal(updated.runtimeChecklist.status, "canceled");
  assert.equal(updated.runtimeJob.eventCount, 5);
  assert.deepEqual(updated.trace.qualityLedger.failureOntologyLabels, ["existing_label", "operator_cancel"]);
  assert.equal(updated.trace.stopCondition.evidenceSufficient, true);
  assert.equal(updated.receipts.at(-1).id, "receipt_run_cancel_one_runtime_checklist");
  assert.equal(updated.artifacts.find((item) => item.name === "runtime-task.json").content.status, "canceled");
  assert.equal(updated.artifacts.find((item) => item.name === "runtime-checklist.json").content.status, "canceled");
  assert.equal(state.runs.get(run.id), updated);
  assert.equal(state.writes.length, 1);
  assert.equal(state.writes[0].operation, "run.cancel");
  assert.equal(state.writes[0].run, updated);
});

test("cancelRun appends runtime task and checklist events when missing", () => {
  const run = {
    id: "run_cancel_missing_projection_events",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel missing projection run",
    mode: "dry_run",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [
      {
        id: "run_cancel_missing_projection_events:event:000:delta",
        type: "delta",
        data: { text: "partial" },
      },
      {
        id: "run_cancel_missing_projection_events:event:001:failed",
        type: "failed",
        data: { status: "failed" },
      },
    ],
    trace: {
      events: [],
      receipts: [],
      qualityLedger: {
        failureOntologyLabels: [],
      },
    },
    receipts: [],
    artifacts: [],
  };
  const state = fakeState(run);
  const calls = [];

  const updated = cancelRun(state, run.id, deps(calls));

  assert.equal(calls[0].operation, "plan_run_cancel_state_update");
  assert.deepEqual(updated.events.map((event) => event.type), [
    "delta",
    "runtime_task",
    "runtime_checklist",
    "job_canceled",
    "canceled",
  ]);
  assert.equal(updated.runtimeTask.taskFamily, "safety_preview");
  assert.equal(updated.runtimeTask.selectedStrategy, "daemon_dry_run_before_effect");
  assert.equal(updated.runtimeJob.eventCount, 5);
  assert.equal(updated.runtimeJob.terminalEventCount, 1);
});

test("cancelRun fails closed without Rust-planned run record", () => {
  const run = {
    id: "run_cancel_missing_plan",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel without a planner result",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [],
    trace: { events: [], receipts: [], qualityLedger: {} },
    receipts: [],
    artifacts: [],
  };
  const state = fakeState(run);
  const calls = [];

  assert.throws(
    () => cancelRun(state, run.id, deps(calls, { status: "planned", operation_kind: "run.cancel", run: null })),
    (error) => {
      assert.equal(error.code, "run_cancel_state_update_planner_invalid");
      assert.equal(error.details.run_id, run.id);
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      return true;
    },
  );
  assert.equal(calls.length, 1);
  assert.equal(state.writes.length, 0);
  assert.equal(state.runs.get(run.id), run);
});

test("cancelRun fails closed without Rust-planned operation kind", () => {
  const run = {
    id: "run_cancel_missing_operation_kind",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel without an operation kind",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [],
    trace: { events: [], receipts: [], qualityLedger: {} },
    receipts: [],
    artifacts: [],
  };
  const state = fakeState(run);
  const calls = [];
  const plannedRun = plannedCancellationRun(run, "2026-06-06T04:45:00.000Z");

  assert.throws(
    () => cancelRun(state, run.id, deps(calls, { status: "planned", run: plannedRun })),
    (error) => {
      assert.equal(error.code, "run_cancel_state_update_operation_kind_missing");
      assert.equal(error.details.run_id, run.id);
      assert.equal(error.details.operation_kind, "run.cancel");
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      return true;
    },
  );
  assert.equal(calls.length, 1);
  assert.equal(state.writes.length, 0);
  assert.equal(state.runs.get(run.id), run);
});

test("cancelRun fails closed with canonical details for mismatched Rust-planned operation kind", () => {
  const run = {
    id: "run_cancel_mismatched_operation_kind",
    agentId: "agent_one",
    status: "running",
    objective: "Cancel with mismatched operation kind",
    mode: "send",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [],
    trace: { events: [], receipts: [], qualityLedger: {} },
    receipts: [],
    artifacts: [],
  };
  const state = fakeState(run);
  const calls = [];
  const plannedRun = plannedCancellationRun(run, "2026-06-06T04:45:00.000Z");

  assert.throws(
    () => cancelRun(state, run.id, deps(calls, {
      status: "planned",
      operation_kind: "run.close",
      run: plannedRun,
    })),
    (error) => {
      assert.equal(error.code, "run_cancel_state_update_operation_kind_mismatch");
      assert.equal(error.details.run_id, run.id);
      assert.equal(error.details.expected_operation_kind, "run.cancel");
      assert.equal(error.details.operation_kind, "run.close");
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      return true;
    },
  );
  assert.equal(calls.length, 1);
  assert.equal(state.writes.length, 0);
  assert.equal(state.runs.get(run.id), run);
});
