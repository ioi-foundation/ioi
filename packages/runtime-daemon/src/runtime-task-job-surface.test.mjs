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
    createAgent(input) {
      calls.push({ name: "createAgent", input });
      return { id: "agent-created" };
    },
    createRun(agentId, input) {
      calls.push({ name: "createRun", agentId, input });
      return run("run-created", "running", "2026-06-04T00:00:03.000Z");
    },
    cancelRun(runId) {
      calls.push({ name: "cancelRun", runId });
      return run(runId, "cancelled", "2026-06-04T00:00:04.000Z");
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

test("runtime task job surface creates task with existing or synthesized agent", () => {
  const { calls, store, surface } = harness();

  assert.equal(surface.createTask(store, { agent_id: "agent-one", prompt: "Do it" }).taskId, "task-run-created");
  assert.equal(surface.createTask(store, {
    cwd: "/workspace/custom",
    model: "route.local-first",
    prompt: "Make it so",
    options: "ignored",
  }).taskId, "task-run-created");
  assert.equal(surface.createTask(store, {
    agentId: "legacy-agent",
    agentOptions: {
      local: { cwd: "/workspace/legacy-options" },
      model: "route.legacy-options",
    },
    workspace: "/workspace/legacy",
    prompt: "Legacy aliases ignored",
    objective: "Retired objective ignored",
    goal: "Retired goal ignored",
  }).taskId, "task-run-created");

  assert.deepEqual(calls.filter((call) => call.name === "getAgent"), [
    { name: "getAgent", agentId: "agent-one" },
  ]);
  const createAgentCalls = calls.filter((call) => call.name === "createAgent");
  assert.deepEqual(createAgentCalls.map((call) => call.input.local), [
    { cwd: "/workspace/custom" },
    { cwd: "/workspace/default" },
  ]);
  assert.deepEqual(createAgentCalls.map((call) => call.input.model), [
    "route.local-first",
    undefined,
  ]);
  assert.deepEqual(calls.filter((call) => call.name === "createRun").map((call) => ({
    agentId: call.agentId,
    mode: call.input.mode,
    prompt: call.input.prompt,
    options: call.input.options,
  })), [
    { agentId: "agent-one", mode: "send", prompt: "Do it", options: {} },
    { agentId: "agent-created", mode: "send", prompt: "Make it so", options: {} },
    { agentId: "agent-created", mode: "send", prompt: "Legacy aliases ignored", options: {} },
  ]);
});

test("runtime task job surface gets and cancels tasks and jobs by public id only", () => {
  const { calls, store, surface } = harness();

  assert.equal(surface.getTask(store, "task-run-a").runId, "run-a");
  assert.equal(surface.getJob(store, "job-run-b").runId, "run-b");
  assert.deepEqual(surface.cancelTask(store, "task-run-a"), {
    taskId: "task-run-a",
    runId: "run-a",
    status: "cancelled",
    createdAt: "2026-06-04T00:00:04.000Z",
  });
  assert.deepEqual(surface.cancelJob(store, "job-run-b"), {
    jobId: "job-run-b",
    runId: "run-b",
    status: "cancelled",
    createdAt: "2026-06-04T00:00:04.000Z",
  });
  assert.deepEqual(calls.filter((call) => call.name === "cancelRun"), [
    { name: "cancelRun", runId: "run-a" },
    { name: "cancelRun", runId: "run-b" },
  ]);
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
