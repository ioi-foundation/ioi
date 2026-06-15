import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeTaskJobSurface } from "./runtime-task-job-surface.mjs";

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
  const surface = createRuntimeTaskJobSurface({
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
  return { calls, store, surface };
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

function plannedTaskJobCreate(request) {
  const runtimeTask = {
    taskId: `task_${request.run.id}`,
    runId: request.run.id,
    agentId: request.agent_id,
    status: "completed",
  };
  const runtimeJob = {
    jobId: `job_${request.run.id}`,
    taskId: runtimeTask.taskId,
    runId: request.run.id,
    agentId: request.agent_id,
    status: "completed",
    checklistId: `checklist_${request.run.id}`,
  };
  const runtimeChecklist = {
    checklistId: `checklist_${request.run.id}`,
    taskId: runtimeTask.taskId,
    jobId: runtimeJob.jobId,
    runId: request.run.id,
    status: "completed",
  };
  return {
    source: "rust_runtime_task_job_create_state_update_api",
    status: "planned",
    operation_kind: "task.create",
    task_id: runtimeTask.taskId,
    job_id: runtimeJob.jobId,
    run_id: request.run.id,
    agent_id: request.agent_id,
    runtime_task: runtimeTask,
    runtime_job: runtimeJob,
    runtime_checklist: runtimeChecklist,
    run: {
      ...request.run,
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
      rust_planned_task_create: true,
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

test("runtime task create commits Rust-planned task/job projection", () => {
  const calls = [];
  const writes = [];
  const agent = {
    id: "agent-one",
    runtime: "local",
    options: {},
    modelId: "model-default",
  };
  const surface = createRuntimeTaskJobSurface({
    buildRun({
      agent: buildAgent,
      mode,
      prompt,
      request,
      source,
      modelRoute,
      memory,
    }) {
      calls.push({
        name: "buildRun",
        agent: buildAgent,
        mode,
        prompt,
        request,
        source,
        modelRoute,
        memory,
      });
      return {
        id: "run-task-create",
        agentId: buildAgent.id,
        status: "completed",
        mode,
        objective: prompt,
        createdAt: "2026-06-06T05:10:00.000Z",
        updatedAt: "2026-06-06T05:10:00.000Z",
        events: [],
        receipts: [],
        artifacts: [],
        usage: {},
        usage_telemetry: {},
        trace: { usage_telemetry: {}, qualityLedger: {} },
      };
    },
    ensureProviderAvailable(runtime, options) {
      calls.push({ name: "ensureProviderAvailable", runtime, options });
    },
    taskJobCreateRunner: {
      planRuntimeTaskJobCreateStateUpdate(request) {
        calls.push({ name: "planRuntimeTaskJobCreateStateUpdate", request });
        return plannedTaskJobCreate(request);
      },
    },
  });
  const store = {
    getAgent(agentId) {
      calls.push({ name: "getAgent", agentId });
      return agent;
    },
    resolveRunModelRoute(resolveAgent, request) {
      calls.push({ name: "resolveRunModelRoute", agent: resolveAgent, request });
      return { selectedModel: "model-default", routeId: "route.local-first" };
    },
    resolveRunMemory(resolveAgent, request, prompt) {
      calls.push({ name: "resolveRunMemory", agent: resolveAgent, request, prompt });
      return { records: [] };
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  const result = surface.createTask(store, {
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
  assert.equal(writes.length, 1);
  assert.equal(writes[0].operationKind, "task.create");
  assert.equal(writes[0].run.rust_planned_task_create, true);
  assert.equal(writes[0].run.runtimeTask.taskId, "task_run-task-create");
  assert.equal(writes[0].run.runtimeJob.jobId, "job_run-task-create");
  assert.equal(writes[0].run.runtimeChecklist.checklistId, "checklist_run-task-create");
  assert.equal(calls[0].name, "getAgent");
  assert.equal(calls[1].name, "ensureProviderAvailable");
  assert.equal(calls[2].name, "resolveRunModelRoute");
  assert.deepEqual(calls[2].request, {
    mode: "send",
    prompt: "Do it",
    options: {
      taskFamily: "runtime",
      model: { id: "model-default" },
      cwd: "/workspace/canonical",
    },
  });
  assert.equal(calls[4].name, "buildRun");
  assert.equal(calls[5].name, "planRuntimeTaskJobCreateStateUpdate");
  assert.deepEqual(calls[5].request, {
    agent_id: "agent-one",
    run: calls[5].request.run,
  });
  assert.equal(calls[5].request.run.id, "run-task-create");
  assert.equal(Object.hasOwn(calls[2].request, "agentId"), false);
  assert.equal(Object.hasOwn(calls[2].request, "objective"), false);
  assert.equal(Object.hasOwn(calls[2].request, "goal"), false);
});

test("runtime task create fails closed before agent lookup when Rust planner is missing", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_create",
        operationKind: "task.create",
      }),
  );

  assert.deepEqual(calls, []);
});

test("runtime task create rejects Rust projection mismatches before persistence", () => {
  const writes = [];
  const agent = { id: "agent-one", runtime: "local", options: {}, modelId: "model-default" };
  const surface = createRuntimeTaskJobSurface({
    buildRun() {
      return {
        id: "run-task-create",
        agentId: "agent-one",
        status: "completed",
        mode: "send",
        createdAt: "2026-06-06T05:10:00.000Z",
        updatedAt: "2026-06-06T05:10:00.000Z",
        events: [],
        receipts: [],
        artifacts: [],
        usage: {},
        usage_telemetry: {},
        trace: { usage_telemetry: {}, qualityLedger: {} },
      };
    },
    taskJobCreateRunner: {
      planRuntimeTaskJobCreateStateUpdate(request) {
        const planned = plannedTaskJobCreate(request);
        planned.runtime_task = { ...planned.runtime_task, taskId: "task_run-other" };
        planned.run = {
          ...planned.run,
          runtimeTask: planned.runtime_task,
        };
        return planned;
      },
    },
  });
  const store = {
    getAgent() {
      return agent;
    },
    resolveRunModelRoute() {
      return { selectedModel: "model-default", routeId: "route.local-first" };
    },
    resolveRunMemory() {
      return { records: [] };
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  assert.throws(
    () => surface.createTask(store, { agent_id: "agent-one", prompt: "Do it" }),
    (error) => {
      assert.equal(error.code, "runtime_task_create_state_update_projection_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.agent_id, "agent-one");
      assert.equal(error.details.task_id, "task_run-task-create");
      assert.equal(error.details.actual_task_id, "task_run-other");
      return true;
    },
  );
  assert.deepEqual(writes, []);
});

test("runtime task cancel commits Rust-planned run cancellation and returns task projection", () => {
  const calls = [];
  const writes = [];
  const existingRun = run("run-a", "running", "2026-06-04T00:00:01.000Z");
  const surface = createRuntimeTaskJobSurface({
    taskJobCancelRunner: {
      planRuntimeTaskJobCancelStateUpdate(request) {
        calls.push({ name: "planRuntimeTaskJobCancelStateUpdate", request });
        return plannedTaskJobCancel(request, "task.cancel");
      },
    },
  });
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

  const result = surface.cancelTask(store, "task_run-a");

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

test("runtime job cancel commits Rust-planned run cancellation and returns job projection", () => {
  const writes = [];
  const existingRun = run("run-b", "running", "2026-06-04T00:00:02.000Z");
  const surface = createRuntimeTaskJobSurface({
    taskJobCancelRunner: {
      planRuntimeTaskJobCancelStateUpdate(request) {
        return plannedTaskJobCancel(request, "job.cancel");
      },
    },
  });
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

  const result = surface.cancelJob(store, "job_run-b");

  assert.equal(result.jobId, "job_run-b");
  assert.equal(result.status, "canceled");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].operationKind, "job.cancel");
  assert.equal(writes[0].run.status, "canceled");
});

test("runtime task job cancel fails closed before run lookup when Rust planner is missing", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.cancelTask(store, "task_run-a"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_task_cancel",
        operationKind: "task.cancel",
        taskId: "task_run-a",
      }),
  );
  assert.throws(
    () => surface.cancelJob(store, "job_run-b"),
    (error) =>
      assertRuntimeTaskJobRustCoreRequired(error, {
        operation: "runtime_job_cancel",
        operationKind: "job.cancel",
        jobId: "job_run-b",
      }),
  );
  assert.deepEqual(calls, []);
});

test("runtime task job cancel rejects Rust projection mismatches before persistence", () => {
  const writes = [];
  const existingRun = run("run-a", "running", "2026-06-04T00:00:01.000Z");
  const surface = createRuntimeTaskJobSurface({
    taskJobCancelRunner: {
      planRuntimeTaskJobCancelStateUpdate(request) {
        const planned = plannedTaskJobCancel(request, "task.cancel");
        planned.runtime_task = { ...planned.runtime_task, taskId: "task_run-other" };
        return planned;
      },
    },
  });
  const store = {
    getRun() {
      return existingRun;
    },
    writeRun(runRecord, operationKind) {
      writes.push({ run: runRecord, operationKind });
    },
  };

  assert.throws(
    () => surface.cancelTask(store, "task_run-a"),
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

test("runtime task job read projection calls Rust state-dir projector for list filters", () => {
  const calls = [];
  const surface = createRuntimeTaskJobSurface({
    taskJobProjectionRunner: {
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
    },
  });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  const result = surface.listTasks(store, {
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

test("runtime task job read projection returns Rust-selected task and job records", () => {
  const calls = [];
  const surface = createRuntimeTaskJobSurface({
    taskJobProjectionRunner: {
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
    },
  });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  const task = surface.getTask(store, "task_run-a");
  const job = surface.getJob(store, "job_run-b");

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

test("runtime task job read projection fails closed before run lookup when Rust projector is missing", () => {
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

test("runtime task job read projection rejects Rust projection mismatches before returning", () => {
  const surface = createRuntimeTaskJobSurface({
    taskJobProjectionRunner: {
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
    },
  });
  const store = {
    stateDir: "/tmp/ioi-runtime-state",
  };

  assert.throws(
    () => surface.getTask(store, "task_run-a"),
    (error) => {
      assert.equal(error.code, "runtime_task_job_projection_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.task_id, "task_run-a");
      assert.equal(error.details.actual_task_id, "task_run-other");
      return true;
    },
  );
});
