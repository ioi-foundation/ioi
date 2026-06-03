import assert from "node:assert/strict";
import { test } from "node:test";

import {
  terminalEventCount,
  writeAgentRecord,
  writeRunRecord,
} from "./thread-persistence.mjs";

function fakeStore() {
  return {
    operations: [],
    writes: [],
    appendOperation(kind, payload) {
      this.operations.push({ kind, payload });
    },
    canonicalProjection(runId) {
      return { runId, projection: "canonical" };
    },
    operationCount() {
      return this.operations.length;
    },
    pathFor(...segments) {
      return segments.join("/");
    },
  };
}

function deps(store) {
  return {
    runtimeChecklistRecordForRun(run) {
      return { checklistId: `checklist_${run.id}`, runId: run.id };
    },
    runtimeJobRecordForRun(run) {
      return { jobId: `job_${run.id}`, runId: run.id };
    },
    runtimeTaskRecordForRun(run) {
      return { taskId: `task_${run.id}`, runId: run.id };
    },
    terminalEventTypes: new Set(["completed", "failed"]),
    writeJson(filePath, value) {
      store.writes.push({ filePath, value });
    },
  };
}

test("thread persistence counts terminal events", () => {
  assert.equal(
    terminalEventCount(
      [{ type: "started" }, { type: "completed" }, { type: "failed" }],
      new Set(["completed", "failed"]),
    ),
    2,
  );
});

test("thread persistence writes agent records and operation entries", () => {
  const store = fakeStore();
  const agent = { id: "agent_1", status: "active" };

  writeAgentRecord(store, agent, "agent.create", deps(store));

  assert.deepEqual(store.writes, [{ filePath: "agents/agent_1.json", value: agent }]);
  assert.deepEqual(store.operations, [
    { kind: "agent.create", payload: { objectId: "agent_1", agent } },
  ]);
});

test("thread persistence writes run projections and summarized operation entry", () => {
  const store = fakeStore();
  const run = {
    id: "run_1",
    agentId: "agent_1",
    status: "completed",
    events: [{ type: "started" }, { type: "completed" }],
    receipts: [
      { id: "receipt_policy", kind: "policy_decision" },
      { id: "receipt_authority", kind: "authority_decision" },
    ],
    artifacts: [{ id: "artifact_1", kind: "text" }],
    trace: {
      taskState: { state: "done" },
      postconditions: [{ id: "postcondition_1" }],
      semanticImpact: { impact: "local" },
      stopCondition: { reason: "done" },
      scorecard: { score: 1 },
      qualityLedger: { entries: [] },
      traceBundleId: "trace_bundle_1",
    },
  };

  writeRunRecord(store, run, "run.create", deps(store));

  const files = store.writes.map((write) => write.filePath);
  assert.deepEqual(files, [
    "runs/run_1.json",
    "tasks/run_1.json",
    "jobs/job_run_1.json",
    "checklists/checklist_run_1.json",
    "receipts/receipt_policy.json",
    "receipts/receipt_authority.json",
    "artifacts/artifact_1.json",
    "policy-decisions/run_1.json",
    "authority-decisions/run_1.json",
    "stop-conditions/run_1.json",
    "scorecards/run_1.json",
    "ledgers/run_1.json",
    "quality/run_1.json",
    "projections/run_1.json",
  ]);
  assert.deepEqual(store.writes.find((write) => write.filePath === "tasks/run_1.json").value, {
    runId: "run_1",
    agentId: "agent_1",
    runtimeTask: { taskId: "task_run_1", runId: "run_1" },
    runtimeChecklist: { checklistId: "checklist_run_1", runId: "run_1" },
    taskState: { state: "done" },
    postconditions: [{ id: "postcondition_1" }],
    semanticImpact: { impact: "local" },
    projectionWatermark: 1,
  });
  assert.deepEqual(store.operations, [
    {
      kind: "run.create",
      payload: {
        objectId: "run_1",
        runId: "run_1",
        agentId: "agent_1",
        status: "completed",
        eventCount: 2,
        terminalEventCount: 1,
        traceBundleId: "trace_bundle_1",
      },
    },
  ]);
});
