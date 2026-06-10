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
    runtimeError({ status, code, message, details }) {
      return Object.assign(new Error(message), { status, code, details });
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

test("runtime task job read projection facades fail closed before JS run reads", () => {
  const { calls, store, surface } = harness();
  const cases = [
    {
      operation: "runtime_task_list",
      operationKind: "task.list",
      call: () => surface.listTasks(store, { agent_id: "agent-one", status: "running" }),
    },
    {
      operation: "runtime_task_get",
      operationKind: "task.get",
      taskId: "task-run-a",
      call: () => surface.getTask(store, "task-run-a"),
    },
    {
      operation: "runtime_job_list",
      operationKind: "job.list",
      call: () => surface.listJobs(store, { agent_id: "agent-one", status: "completed" }),
    },
    {
      operation: "runtime_job_get",
      operationKind: "job.get",
      jobId: "job-run-b",
      call: () => surface.getJob(store, "job-run-b"),
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertRuntimeTaskJobRustCoreRequired(error, testCase),
    );
  }

  assert.deepEqual(calls, []);
});
