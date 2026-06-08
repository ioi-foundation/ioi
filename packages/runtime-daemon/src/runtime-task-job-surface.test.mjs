import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeTaskJobSurface } from "./runtime-task-job-surface.mjs";

function run(id, status, createdAt) {
  return { id, status, createdAt, agentId: "agent-one" };
}

function harness() {
  const calls = [];
  const runs = [
    run("run-b", "completed", "2026-06-04T00:00:02.000Z"),
    run("run-a", "running", "2026-06-04T00:00:01.000Z"),
  ];
  const surface = createRuntimeTaskJobSurface({
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    optionalString(value) {
      return typeof value === "string" && value.trim() ? value.trim() : null;
    },
    runtimeJobRecordForRun(input) {
      return {
        jobId: `job-${input.id}`,
        runId: input.id,
        status: input.status,
        createdAt: input.createdAt,
      };
    },
    runtimeTaskRecordForRun(input) {
      return {
        taskId: `task-${input.id}`,
        runId: input.id,
        status: input.status,
        createdAt: input.createdAt,
      };
    },
  });
  const store = {
    defaultCwd: "/workspace/default",
    listRuns(agentId) {
      calls.push({ name: "listRuns", agentId });
      return runs;
    },
    getAgent(agentId) {
      calls.push({ name: "getAgent", agentId });
      return { id: agentId };
    },
  };
  return { calls, store, surface };
}

function thrownBy(callback) {
  try {
    callback();
  } catch (error) {
    return error;
  }
  assert.fail("Expected callback to throw");
}

test("runtime task job surface lists and filters task and job projections with canonical request fields", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.listTasks(store).map((task) => task.taskId), ["task-run-a", "task-run-b"]);
  assert.deepEqual(surface.listJobs(store, { status: "completed" }), [
    {
      jobId: "job-run-b",
      runId: "run-b",
      status: "completed",
      createdAt: "2026-06-04T00:00:02.000Z",
    },
  ]);
  assert.deepEqual(surface.listTasks(store, { agent_id: "agent-two" }).map((task) => task.taskId), ["task-run-a", "task-run-b"]);
  assert.deepEqual(surface.listJobs(store, { agentId: "legacy-agent", status: "running" }).map((job) => job.jobId), ["job-run-a"]);
  assert.deepEqual(calls, [
    { name: "listRuns", agentId: undefined },
    { name: "listRuns", agentId: undefined },
    { name: "listRuns", agentId: "agent-two" },
    { name: "listRuns", agentId: undefined },
  ]);
});

test("runtime task job surface default projections ignore retired task and job id fallbacks", () => {
  const runs = [
    {
      id: "run-canonical",
      runtimeTask: { taskId: "task-retired-nested" },
      taskId: "task-retired-top",
      runtimeJob: { jobId: "job-retired-nested" },
      jobId: "job-retired-top",
      status: "running",
      createdAt: "2026-06-04T00:00:05.000Z",
    },
  ];
  const surface = createRuntimeTaskJobSurface();
  const store = {
    listRuns() {
      return runs;
    },
  };

  assert.deepEqual(surface.listTasks(store), [
    {
      taskId: "run-canonical",
      runId: "run-canonical",
      status: "running",
      createdAt: "2026-06-04T00:00:05.000Z",
    },
  ]);
  assert.deepEqual(surface.listJobs(store), [
    {
      jobId: "run-canonical",
      runId: "run-canonical",
      status: "running",
      createdAt: "2026-06-04T00:00:05.000Z",
    },
  ]);
});

function assertRuntimeTaskJobRustCoreRequired(error, {
  operation,
  operationKind,
  taskId = null,
  jobId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_task_job_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.task_job_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  if (taskId) assert.equal(error.details.task_id, taskId);
  if (jobId) assert.equal(error.details.job_id, jobId);
  assert.equal(error.details.evidence_refs.includes("runtime_task_job_control_js_facade_retired"), true);
  assert.equal(error.details.evidence_refs.includes(`${operation}_js_facade_retired`), true);
  assert.equal(
    error.details.evidence_refs.includes("rust_daemon_core_runtime_task_job_control_required"),
    true,
  );
  return true;
}

test("runtime task job mutation facades fail closed before JS lifecycle mutation", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_create",
        operationKind: "task.create",
      }),
  );
  assert.throws(
    () => surface.cancelTask(store, "task-run-a"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_cancel",
        operationKind: "task.cancel",
        taskId: "task-run-a",
      }),
  );
  assert.throws(
    () => surface.cancelJob(store, "job-run-b"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_job_cancel",
        operationKind: "job.cancel",
        jobId: "job-run-b",
      }),
  );

  assert.deepEqual(calls, []);
});

test("runtime task job surface gets tasks and jobs by public id only", () => {
  const { calls, store, surface } = harness();

  assert.equal(surface.getTask(store, "task-run-a").runId, "run-a");
  assert.equal(surface.getJob(store, "job-run-b").runId, "run-b");
  assert.deepEqual(calls.filter((call) => call.name === "listRuns").length, 2);
  const runIdTask = thrownBy(() => surface.getTask(store, "run-a"));
  assert.match(runIdTask.message, /Task not found/);
  assert.equal(runIdTask.details.task_id, "run-a");
  const runIdJob = thrownBy(() => surface.getJob(store, "run-b"));
  assert.match(runIdJob.message, /Job not found/);
  assert.equal(runIdJob.details.job_id, "run-b");
  const missingTask = thrownBy(() => surface.getTask(store, "missing"));
  assert.match(missingTask.message, /Task not found/);
  assert.equal(missingTask.details.task_id, "missing");
  assert.equal(Object.hasOwn(missingTask.details, "taskId"), false);
  const missingJob = thrownBy(() => surface.getJob(store, "missing"));
  assert.match(missingJob.message, /Job not found/);
  assert.equal(missingJob.details.job_id, "missing");
  assert.equal(Object.hasOwn(missingJob.details, "jobId"), false);
});
