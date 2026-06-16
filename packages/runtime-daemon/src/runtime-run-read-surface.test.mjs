import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRunReadSurface } from "./runtime-run-read-surface.mjs";

function run(id, agentId = "agent-one", createdAt = "2026-06-04T00:00:00.000Z") {
  return {
    id,
    agentId,
    createdAt,
    status: "completed",
    events: [{ id: `${id}:event:1` }, { id: `${id}:event:2` }],
    trace: {
      stopCondition: { reason: "done" },
      scorecard: { status: "pass" },
    },
  };
}

function harness() {
  const calls = [];
  const runs = new Map([
    ["run-one", run("run-one")],
    ["run-two", run("run-two", "agent-two", "2026-06-04T00:00:01.000Z")],
  ]);
  const store = {
    schemaVersion: "schema.v1",
    stateDir: "/state",
    runs,
    agents: new Map([
      ["agent-one", { id: "agent-one" }],
      ["agent-two", { id: "agent-two" }],
    ]),
    subagents: new Map([
      ["sub-one", { id: "sub-one", parent_thread_id: "thread-agent-one" }],
      ["sub-two", { id: "sub-two", parent_thread_id: "thread-agent-two" }],
      ["sub-retired", { id: "sub-retired", parentThreadId: "thread-agent-two" }],
    ]),
    getAgent(agentId) {
      return this.agents.get(agentId);
    },
    agentForThread(threadId) {
      const agentId = threadId.replace(/^thread-/, "");
      return this.getAgent(agentId);
    },
    getRun(runId) {
      return this.runReadSurface.getRun(this, runId);
    },
    listRuns(agentId) {
      return this.runReadSurface.listRuns(this, agentId);
    },
    eventsForRun(runId, cursor) {
      calls.push({ name: "eventsForRun", runId, cursor });
      return [{ id: "canonical-event", cursor }];
    },
    pathFor(...segments) {
      return ["/state", ...segments].join("/");
    },
  };
  const surface = createRuntimeRunReadSurface({
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    runtimeUsageTelemetryForRun({ run, agent, threadId }) {
      return { scope: "run", runId: run.id, agentId: agent?.id, threadId };
    },
    runtimeUsageTelemetryForThread({ threadId, agent, runs, subagents }) {
      return {
        scope: "thread",
        threadId,
        agentId: agent?.id,
        runIds: runs.map((candidate) => candidate.id),
        subagentIds: subagents.map((candidate) => candidate.id),
      };
    },
    threadIdForAgent(agentId) {
      return `thread-${agentId}`;
    },
  });
  store.runReadSurface = surface;
  return { calls, store, surface };
}

test("runtime run read surface delegates get/list and usage projections", () => {
  const { store, surface } = harness();

  assert.equal(surface.getRun(store, "run-one").id, "run-one");
  assert.deepEqual(surface.listRuns(store, "agent-two").map((candidate) => candidate.id), ["run-two"]);
  assert.deepEqual(surface.usageForRun(store, "run-one"), {
    scope: "run",
    runId: "run-one",
    agentId: "agent-one",
    threadId: "thread-agent-one",
  });
  assert.deepEqual(surface.usageForThread(store, "thread-agent-one"), {
    scope: "thread",
    threadId: "thread-agent-one",
    agentId: "agent-one",
    runIds: ["run-one"],
    subagentIds: ["sub-one"],
  });
  assert.equal(Object.hasOwn(surface, "listUsage"), false);
  assert.throws(() => surface.getRun(store, "missing"), /Run not found/);
});

test("runtime run read surface keeps authority evidence retired and projects trace/canonical paths", () => {
  const { store, surface } = harness();

  assert.equal(Object.hasOwn(surface, "authorityEvidenceSummary"), false);
  assert.equal(Object.hasOwn(surface, "legacyEventsForRun"), false);
  assert.equal(Object.hasOwn(surface, "replayFromCanonicalState"), false);
  assert.deepEqual(surface.traceFromCanonicalState(store, "run-one"), {
    stopCondition: { reason: "done" },
    scorecard: { status: "pass" },
  });
  const canonicalProjection = surface.canonicalProjection(store, "run-one");
  assert.deepEqual(canonicalProjection, {
    schemaVersion: "schema.v1",
    runId: "run-one",
    source: "agentgres_canonical_state_projection",
    watermark: 2,
    freshness: {
      source: "local-agentgres-v0",
      runStateWatermark: 2,
      generatedAt: canonicalProjection.freshness.generatedAt,
    },
    paths: {
      run: "runs/run-one.json",
      task: "tasks/run-one.json",
      job: "jobs/job_run-one.json",
      checklist: "checklists/checklist_run-one.json",
      quality: "quality/run-one.json",
    },
    terminalState: "completed",
    stopCondition: { reason: "done" },
    scorecard: { status: "pass" },
  });
});

test("runtime run read surface default job sidecar path ignores retired job id fallbacks", () => {
  const poisonedRun = {
    ...run("run-canonical"),
    runtimeJob: { jobId: "job-retired-nested" },
    jobId: "job-retired-top",
  };
  const store = {
    schemaVersion: "schema.v1",
    stateDir: "/state",
    runs: new Map([["run-canonical", poisonedRun]]),
    getRun(runId) {
      return this.runs.get(runId);
    },
    pathFor(...segments) {
      return ["/state", ...segments].join("/");
    },
  };
  const surface = createRuntimeRunReadSurface();

  assert.equal(
    surface.canonicalProjection(store, "run-canonical").paths.job,
    "jobs/job_run-canonical.json",
  );
});

test("runtime run read surface default checklist sidecar path ignores retired checklist id fallbacks", () => {
  const poisonedRun = {
    ...run("run-canonical"),
    runtimeChecklist: { checklistId: "checklist-retired-nested" },
    checklistId: "checklist-retired-top",
  };
  const store = {
    schemaVersion: "schema.v1",
    stateDir: "/state",
    runs: new Map([["run-canonical", poisonedRun]]),
    getRun(runId) {
      return this.runs.get(runId);
    },
    pathFor(...segments) {
      return ["/state", ...segments].join("/");
    },
  };
  const surface = createRuntimeRunReadSurface();

  assert.equal(
    surface.canonicalProjection(store, "run-canonical").paths.checklist,
    "checklists/checklist_run-canonical.json",
  );
});
