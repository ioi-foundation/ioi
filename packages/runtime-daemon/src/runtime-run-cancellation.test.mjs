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

function deps() {
  return {
    JOB_TERMINAL_EVENT_TYPES,
    TERMINAL_EVENT_TYPES,
    artifact,
    attachChecklistToRuntimeJob,
    makeEvent: runHelpers.makeEvent,
    normalizeArray,
    runtimeChecklistRecord,
    runtimeJobRecord,
    runtimeTaskRecord,
    strategyForMode: runHelpers.strategyForMode,
    taskFamilyForMode: runHelpers.taskFamilyForMode,
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

  const updated = cancelRun(state, run.id, deps());

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

  const updated = cancelRun(state, run.id, deps());

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
