import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRecordProjections } from "./runtime-record-projections.mjs";

function assertMissingKeys(record, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(record, key), false, `retired alias key ${key} must be absent`);
  }
}

function projections(overrides = {}) {
  return createRuntimeRecordProjections({
    doctorHash: (value) => `hash_${String(value).length}`,
    eventStreamIdForThread: (threadId) => `stream_${threadId}`,
    normalizeArray: (value) => (Array.isArray(value) ? value : []),
    optionalString: (value) => (typeof value === "string" && value.length > 0 ? value : null),
    runtimeSessionIdForAgent: (agent) => `session_${agent.id}`,
    runtimeUsageTelemetryForRun: () => ({
      object: "ioi.runtime_usage_telemetry",
      scope: "run",
      run_id: "run_bridge",
      thread_id: "thread_agent_bridge",
      total_tokens: 42,
    }),
    safeId: (value) => String(value ?? "none").replace(/[^a-zA-Z0-9_-]+/g, "_"),
    strategyForMode: () => "agent",
    taskFamilyForMode: () => "coding",
    terminalCount: (events) => events.length,
    threadIdForAgent: (agentId) => `thread_${agentId}`,
    turnIdForRun: (runId) => `turn_${runId}`,
    uniqueStrings: (values) => [...new Set(values.filter(Boolean).map(String))],
    ...overrides,
  });
}

test("runtime task job checklist records for run ignore embedded sidecar identity aliases", () => {
  const runtime = projections();
  const run = {
    id: "run_canonical",
    agentId: "agent_record",
    objective: "Project canonical records",
    mode: "send",
    status: "completed",
    createdAt: "2026-06-07T00:00:00.000Z",
    updatedAt: "2026-06-07T00:00:01.000Z",
    runtimeTask: {
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    runtimeJob: {
      jobId: "job_retired_embedded",
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    runtimeChecklist: {
      checklistId: "checklist_retired_embedded",
      jobId: "job_retired_embedded",
      taskId: "task_retired_embedded",
      runId: "run_retired",
      status: "failed",
    },
    trace: {
      qualityLedger: {
        taskFamily: "coding",
        selectedStrategy: "agent",
      },
    },
  };

  const task = runtime.runtimeTaskRecordForRun(run);
  const job = runtime.runtimeJobRecordForRun(run);
  const checklist = runtime.runtimeChecklistRecordForRun(run);

  assert.equal(task.taskId, "task_run_canonical");
  assert.equal(task.runId, "run_canonical");
  assert.equal(task.status, "completed");
  assert.equal(job.jobId, "job_run_canonical");
  assert.equal(job.taskId, "task_run_canonical");
  assert.equal(job.runId, "run_canonical");
  assert.equal(job.status, "completed");
  assert.equal(checklist.checklistId, "checklist_run_canonical");
  assert.equal(checklist.jobId, "job_run_canonical");
  assert.equal(checklist.taskId, "task_run_canonical");
  assert.equal(checklist.runId, "run_canonical");
  assert.equal(checklist.status, "completed");
});
