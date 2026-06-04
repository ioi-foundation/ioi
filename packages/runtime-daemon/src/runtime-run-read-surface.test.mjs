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
      ["sub-two", { id: "sub-two", parentThreadId: "thread-agent-two" }],
    ]),
    runtimeEventStreams: new Map([
      ["stream-one", { events: [{ event_id: "event-one" }] }],
      ["stream-two", { events: [{ event_id: "event-two" }] }],
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
    operationCount() {
      return 42;
    },
    pathFor(...segments) {
      return ["/state", ...segments].join("/");
    },
    projectThreadEvents(agent) {
      calls.push({ name: "projectThreadEvents", agentId: agent.id });
    },
  };
  const surface = createRuntimeRunReadSurface({
    authorityEvidenceSummaryForEvents(events, options) {
      calls.push({ name: "authorityEvidenceSummaryForEvents", events, options });
      return { eventCount: events.length, options };
    },
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    runtimeChecklistRecordForRun(input) {
      return { checklistId: `checklist-${input.id}` };
    },
    runtimeJobRecordForRun(input) {
      return { jobId: `job-${input.id}` };
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
    runtimeUsageTelemetryList({ runs, subagents, groupBy }) {
      return {
        groupBy,
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
  assert.deepEqual(surface.listUsage(store, { agentId: "agent-two", groupBy: "thread" }), {
    groupBy: "thread",
    runIds: ["run-two"],
    subagentIds: ["sub-two"],
  });
  assert.throws(() => surface.getRun(store, "missing"), /Run not found/);
});

test("runtime run read surface projects authority evidence, replay, trace, and canonical paths", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.authorityEvidenceSummary(store, { group: "all" }), {
    eventCount: 2,
    options: { group: "all" },
  });
  assert.deepEqual(calls.slice(0, 3).map((call) => call.name), [
    "projectThreadEvents",
    "projectThreadEvents",
    "authorityEvidenceSummaryForEvents",
  ]);
  assert.deepEqual(surface.legacyEventsForRun(store, "run-one", "run-one:event:1"), [
    { id: "run-one:event:2" },
  ]);
  assert.deepEqual(surface.replayFromCanonicalState(store, "run-one", { sinceSeq: 3 }), [
    { id: "canonical-event", cursor: { sinceSeq: 3 } },
  ]);
  assert.deepEqual(surface.traceFromCanonicalState(store, "run-one"), {
    stopCondition: { reason: "done" },
    scorecard: { status: "pass" },
  });
  const canonicalProjection = surface.canonicalProjection(store, "run-one");
  assert.deepEqual(canonicalProjection, {
    schemaVersion: "schema.v1",
    runId: "run-one",
    source: "agentgres_canonical_operation_log",
    watermark: 42,
    freshness: {
      source: "local-agentgres-v0",
      operationCount: 42,
      generatedAt: canonicalProjection.freshness.generatedAt,
    },
    paths: {
      run: "runs/run-one.json",
      task: "tasks/run-one.json",
      job: "jobs/job-run-one.json",
      checklist: "checklists/checklist-run-one.json",
      quality: "quality/run-one.json",
      operationLog: "operation-log.jsonl",
    },
    terminalState: "completed",
    stopCondition: { reason: "done" },
    scorecard: { status: "pass" },
  });
});
