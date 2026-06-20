import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeTaskJobApi } from "./runtime-task-job-api.mjs";

function run(id, status, createdAt) {
  return {
    id,
    status,
    createdAt,
    updatedAt: createdAt,
    agentId: "agent-one",
    events: [{ type: "delta" }],
    receipts: [],
    artifacts: [],
  };
}

function harness() {
  const calls = [];
  const runs = [
    run("run-b", "completed", "2026-06-04T00:00:02.000Z"),
    run("run-a", "running", "2026-06-04T00:00:01.000Z"),
  ];
  const api = createRuntimeTaskJobApi({
    runtimeError({ status, code, message, details }) {
      return Object.assign(new Error(message), { status, code, details });
    },
  });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
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
  return { calls, store, api };
}

function plannedTaskJobCancel(request, operationKind) {
  const runtimeTask = {
    taskId: `task_${request.run_id}`,
    runId: request.run_id,
    status: "canceled",
  };
  const runtimeJob = {
    jobId: `job_${request.run_id}`,
    runId: request.run_id,
    status: "canceled",
  };
  const runtimeChecklist = {
    checklistId: `checklist_${request.run_id}`,
    runId: request.run_id,
    status: "canceled",
  };
  return {
    source: "rust_runtime_task_job_cancel_state_update_api",
    status: "planned",
    operation_kind: operationKind,
    cancel_kind: request.cancel_kind,
    task_id: request.task_id ?? null,
    job_id: request.job_id ?? null,
    run_id: request.run_id,
    runtime_task: runtimeTask,
    runtime_job: runtimeJob,
    runtime_checklist: runtimeChecklist,
    run: {
      ...request.run,
      status: "canceled",
      updatedAt: request.canceled_at,
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
      events: [
        ...request.run.events,
        { type: "job_canceled", data: runtimeJob },
        { type: "canceled", data: { reason: "operator_cancel" } },
      ],
      receipts: [{ id: "receipt_task_job_cancel" }],
      artifacts: [{ id: "artifact_task_job_cancel" }],
    },
  };
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

test("runtime task create uses store-owned run lifecycle and Rust replay projection", async () => {
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeTaskJobProjection(request) {
      calls.push({ name: "projectRuntimeTaskJobProjection", request });
      return {
        source: "rust_runtime_task_job_projection_api",
        status: "projected",
        operation_kind: "task.get",
        projection_kind: "task.get",
        records: [
          {
            taskId: "task_run-task-create",
            runId: "run-task-create",
            agentId: "agent-one",
            status: "completed",
          },
        ],
        runtime_task: {
          taskId: "task_run-task-create",
          runId: "run-task-create",
          agentId: "agent-one",
          status: "completed",
        },
      };
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
    createRun(agentId, request) {
      calls.push({ name: "createRun", agentId, request });
      return {
        id: "run-task-create",
        agentId,
        status: "completed",
        runtimeTask: {
          taskId: "task_run-task-create",
          runId: "run-task-create",
          agentId,
          status: "completed",
        },
      };
    },
  };

  const result = await api.createTask(store, {
    agent_id: "agent-one",
    agentId: "legacy-agent",
    prompt: "Do it",
    objective: "Retired objective ignored",
    goal: "Retired goal ignored",
    options: { taskFamily: "runtime" },
    model: { id: "model-default" },
    cwd: "/workspace/canonical",
  });

  assert.equal(result.taskId, "task_run-task-create");
  assert.equal(result.agentId, "agent-one");
  assert.equal(calls[0].name, "createRun");
  assert.equal(calls[0].agentId, "agent-one");
  assert.deepEqual(calls[0].request, {
    mode: "send",
    prompt: "Do it",
    options: {
      taskFamily: "runtime",
      model: { id: "model-default" },
      cwd: "/workspace/canonical",
    },
  });
  assert.equal(calls[1].name, "projectRuntimeTaskJobProjection");
  assert.deepEqual(calls[1].request, {
    projection_kind: "task.get",
    state_dir: "/tmp/ioi-runtime-state",
    task_id: "task_run-task-create",
  });
  assert.equal(Object.hasOwn(calls[0].request, "agentId"), false);
  assert.equal(Object.hasOwn(calls[0].request, "objective"), false);
  assert.equal(Object.hasOwn(calls[0].request, "goal"), false);
  assert.equal(Object.hasOwn(calls[1].request, "run"), false);
});

test("runtime task create fails closed before run lifecycle when store API is missing", async () => {
  const { calls, store, api } = harness();

  await assert.rejects(async () => api.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_task_create_run_lifecycle_unavailable");
      assert.equal(error.details.rust_core_boundary, "runtime.task_job_control");
      assert.equal(error.details.operation, "runtime_task_create");
      assert.equal(error.details.operation_kind, "task.create");
      assert.equal(
        error.details.evidence_refs.includes("runtime_run_create_state_update_required"),
        true,
      );
      return true;
    },
  );

  assert.deepEqual(calls, []);
});

test("runtime task create fails closed before run lifecycle when Rust projector is missing", async () => {
  const calls = [];
  const api = createRuntimeTaskJobApi({});
  const store = {
    createRun() {
      calls.push({ name: "createRun" });
      return { id: "run-task-create", agentId: "agent-one" };
    },
  };

  await assert.rejects(async () => api.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_create_projection",
        operationKind: "task.get",
      }),
  );
  assert.deepEqual(calls, []);
});

test("runtime task create rejects Rust replay projection mismatches", async () => {
  const contextPolicyCore = {
    projectRuntimeTaskJobProjection() {
      return {
        source: "rust_runtime_task_job_projection_api",
        status: "projected",
        operation_kind: "task.get",
        projection_kind: "task.get",
        records: [{ taskId: "task_run-other", runId: "run-task-create", agentId: "agent-one" }],
        runtime_task: { taskId: "task_run-other", runId: "run-task-create", agentId: "agent-one" },
      };
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
    createRun() {
      return {
        id: "run-task-create",
        agentId: "agent-one",
        status: "completed",
        runtimeTask: { taskId: "task_run-task-create", runId: "run-task-create", agentId: "agent-one" },
      };
    },
  };

  await assert.rejects(async () => api.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) => {
      assert.equal(error.code, "runtime_task_create_projection_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.agent_id, "agent-one");
      assert.equal(error.details.task_id, "task_run-task-create");
      assert.equal(error.details.actual_task_id, "task_run-other");
      return true;
    },
  );
});

test("runtime task cancel commits Rust-planned run cancellation and returns task projection", async () => {
  const calls = [];
  const writes = [];
  const existingRun = run("run-a", "running", "2026-06-04T00:00:01.000Z");
  const contextPolicyCore = {
    planRuntimeTaskJobCancelStateUpdate(request) {
      calls.push({ name: "planRuntimeTaskJobCancelStateUpdate", request });
      return plannedTaskJobCancel(request, "task.cancel");
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    nowIso: () => "2026-06-06T05:00:00.000Z",
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return existingRun;
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  const result = api.cancelTask(store, "task_run-a");

  assert.equal(result.taskId, "task_run-a");
  assert.equal(result.status, "canceled");
  assert.equal(calls[0].name, "getRun");
  assert.equal(calls[0].runId, "run-a");
  assert.equal(calls[1].name, "planRuntimeTaskJobCancelStateUpdate");
  assert.deepEqual(calls[1].request, {
    cancel_kind: "task",
    task_id: "task_run-a",
    run_id: "run-a",
    run: existingRun,
    canceled_at: "2026-06-06T05:00:00.000Z",
  });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].operationKind, "task.cancel");
  assert.equal(writes[0].run.status, "canceled");
  assert.equal(writes[0].run.events.at(-2).type, "job_canceled");
  assert.equal(writes[0].run.events.at(-1).type, "canceled");
});

test("runtime job cancel commits Rust-planned run cancellation and returns job projection", async () => {
  const writes = [];
  const existingRun = run("run-b", "running", "2026-06-04T00:00:02.000Z");
  const contextPolicyCore = {
    planRuntimeTaskJobCancelStateUpdate(request) {
      return plannedTaskJobCancel(request, "job.cancel");
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    nowIso: () => "2026-06-06T05:01:00.000Z",
    getRun(runId) {
      assert.equal(runId, "run-b");
      return existingRun;
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  const result = api.cancelJob(store, "job_run-b");

  assert.equal(result.jobId, "job_run-b");
  assert.equal(result.status, "canceled");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].operationKind, "job.cancel");
  assert.equal(writes[0].run.status, "canceled");
});

test("runtime task job cancel fails closed before run lookup when Rust planner is missing", async () => {
  const { calls, store, api } = harness();

  await assert.rejects(async () => api.cancelTask(store, "task_run-a"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_cancel",
        operationKind: "task.cancel",
        taskId: "task_run-a",
      }),
  );
  await assert.rejects(async () => api.cancelJob(store, "job_run-b"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_job_cancel",
        operationKind: "job.cancel",
        jobId: "job_run-b",
      }),
  );
  assert.deepEqual(calls, []);
});

test("runtime task job cancel rejects Rust projection mismatches before persistence", async () => {
  const writes = [];
  const existingRun = run("run-a", "running", "2026-06-04T00:00:01.000Z");
  const contextPolicyCore = {
    planRuntimeTaskJobCancelStateUpdate(request) {
      const planned = plannedTaskJobCancel(request, "task.cancel");
      planned.runtime_task = { ...planned.runtime_task, taskId: "task_run-other" };
      return planned;
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    getRun() {
      return existingRun;
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  await assert.rejects(async () => api.cancelTask(store, "task_run-a"),
    (error) => {
      assert.equal(error.code, "runtime_task_job_cancel_state_update_projection_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.task_job_control");
      assert.equal(error.details.task_id, "task_run-a");
      assert.equal(error.details.actual_task_id, "task_run-other");
      return true;
    },
  );
  assert.deepEqual(writes, []);
});

test("runtime task job read projection calls Rust state-dir projector for list filters", async () => {
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeTaskJobProjection(request) {
      calls.push({ name: "projectRuntimeTaskJobProjection", request });
      return {
        source: "rust_runtime_task_job_projection_api",
        status: "projected",
        operation_kind: request.projection_kind,
        projection_kind: request.projection_kind,
        records: [
          {
            taskId: "task_run-a",
            runId: "run-a",
            agentId: request.agent_id,
            status: "running",
          },
        ],
        record_count: 1,
      };
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  const result = api.listTasks(store, {
    agent_id: "agent-one",
    agentId: "legacy-agent",
    status: "running",
  });

  assert.deepEqual(result, [
    {
      taskId: "task_run-a",
      runId: "run-a",
      agentId: "agent-one",
      status: "running",
    },
  ]);
  assert.equal(calls[0].name, "projectRuntimeTaskJobProjection");
  assert.deepEqual(calls[0].request, {
    projection_kind: "task.list",
    state_dir: "/tmp/ioi-runtime-state",
    agent_id: "agent-one",
    status: "running",
  });
  assert.equal(Object.hasOwn(calls[0].request, "runs"), false);
});

test("runtime task job read projection returns Rust-selected task and job records", async () => {
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeTaskJobProjection(request) {
      calls.push({ name: "projectRuntimeTaskJobProjection", request });
      if (request.projection_kind === "task.get") {
        return {
          source: "rust_runtime_task_job_projection_api",
          status: "projected",
          operation_kind: "task.get",
          projection_kind: "task.get",
          task_id: request.task_id,
          records: [{ taskId: request.task_id, runId: "run-a", status: "running" }],
          runtime_task: { taskId: request.task_id, runId: "run-a", status: "running" },
          record_count: 1,
        };
      }
      return {
        source: "rust_runtime_task_job_projection_api",
        status: "projected",
        operation_kind: "job.get",
        projection_kind: "job.get",
        job_id: request.job_id,
        records: [{ jobId: request.job_id, runId: "run-b", status: "completed" }],
        runtime_job: { jobId: request.job_id, runId: "run-b", status: "completed" },
        record_count: 1,
      };
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  const task = api.getTask(store, "task_run-a");
  const job = api.getJob(store, "job_run-b");

  assert.equal(task.taskId, "task_run-a");
  assert.equal(job.jobId, "job_run-b");
  assert.deepEqual(calls[0].request, {
    projection_kind: "task.get",
    state_dir: "/tmp/ioi-runtime-state",
    task_id: "task_run-a",
  });
  assert.deepEqual(calls[1].request, {
    projection_kind: "job.get",
    state_dir: "/tmp/ioi-runtime-state",
    job_id: "job_run-b",
  });
  assert.equal(Object.hasOwn(calls[0].request, "runs"), false);
  assert.equal(Object.hasOwn(calls[1].request, "runs"), false);
});

test("runtime task job read projection fails closed before run lookup when Rust projector is missing", async () => {
  const { calls, store, api } = harness();
  const cases = [
    {
      operation: "runtime_task_list",
      operationKind: "task.list",
      call: () => api.listTasks(store, { agent_id: "agent-one", status: "running" }),
    },
    {
      operation: "runtime_task_get",
      operationKind: "task.get",
      taskId: "task-run-a",
      call: () => api.getTask(store, "task-run-a"),
    },
    {
      operation: "runtime_job_list",
      operationKind: "job.list",
      call: () => api.listJobs(store, { agent_id: "agent-one", status: "completed" }),
    },
    {
      operation: "runtime_job_get",
      operationKind: "job.get",
      jobId: "job-run-b",
      call: () => api.getJob(store, "job-run-b"),
    },
  ];

  for (const testCase of cases) {
    await assert.rejects(async () => testCase.call(),
      (error) => assertRuntimeTaskJobRustCoreRequired(error, testCase),
    );
  }

  assert.deepEqual(calls, []);
});

test("runtime task job read projection rejects Rust projection mismatches before returning", async () => {
  const contextPolicyCore = {
    projectRuntimeTaskJobProjection(request) {
      return {
        source: "rust_runtime_task_job_projection_api",
        status: "projected",
        operation_kind: request.projection_kind,
        projection_kind: request.projection_kind,
        records: [{ taskId: "task_run-other", runId: "run-other" }],
        runtime_task: { taskId: "task_run-other", runId: "run-other" },
        record_count: 1,
      };
    },
  };
  const api = createRuntimeTaskJobApi({ contextPolicyCore });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  await assert.rejects(async () => api.getTask(store, "task_run-a"),
    (error) => {
      assert.equal(error.code, "runtime_task_job_projection_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.task_id, "task_run-a");
      assert.equal(error.details.actual_task_id, "task_run-other");
      return true;
    },
  );
});
