import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  ensureStateDirs,
  loadStateRecords,
  removeQuietFile,
  RUNTIME_STATE_DIRS,
  statePathFor,
  terminalEventCount,
  writeAgentRecord,
  writeRunRecord,
  writeStateSchema,
  writeSubagentRecord,
} from "./thread-persistence.mjs";

function fakeStore() {
  return {
    operations: [],
    stateDir: "/runtime-state",
    agents: new Map(),
    codingArtifacts: new Map(),
    modelMounting: {
      writeSchemaRelationSchemas() {
        return { modelRoutes: ["id", "providerId"] };
      },
    },
    registeredEvents: [],
    runs: new Map(),
    schemaVersion: "ioi.agentgres.runtime.v0",
    subagents: new Map(),
    writes: [],
    canonicalProjection(runId) {
      return { runId, projection: "canonical" };
    },
    pathFor(...segments) {
      return segments.join("/");
    },
    registerRuntimeEvent(record) {
      this.registeredEvents.push(record);
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

test("thread persistence writes agent records without operation entries", () => {
  const store = fakeStore();
  const agent = { id: "agent_1", status: "active" };

  writeAgentRecord(store, agent, "agent.create", deps(store));

  assert.deepEqual(store.writes, [{ filePath: "agents/agent_1.json", value: agent }]);
  assert.deepEqual(store.operations, []);
});

test("thread persistence writes subagent records without operation entries", () => {
  const store = fakeStore();
  const subagent = {
    subagentId: "subagent_1",
    parentThreadId: "thread_1",
    agentId: "agent_1",
    lifecycle_status: "running",
    role: "research",
  };

  writeSubagentRecord(store, subagent, "subagent.spawn", deps(store));

  assert.equal(store.subagents.get("subagent_1"), subagent);
  assert.deepEqual(store.writes, [{ filePath: "subagents/subagent_1.json", value: subagent }]);
  assert.deepEqual(store.operations, []);
});

test("thread persistence rejects subagent records without stable ids", () => {
  const store = fakeStore();

  assert.throws(
    () => writeSubagentRecord(store, {}, "subagent.spawn", {
      ...deps(store),
      runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
    }),
    (error) => error.status === 500 && error.code === "subagent_id_required",
  );
});

test("thread persistence resolves state paths and quiet removal without operation logs", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-thread-persistence-"));
  const store = { stateDir };

  assert.equal(statePathFor(store, "projections", "run_1.json"), path.join(stateDir, "projections", "run_1.json"));

  const temporaryFile = path.join(stateDir, "projection.json");
  fs.writeFileSync(temporaryFile, "{}");
  removeQuietFile(temporaryFile);
  removeQuietFile(temporaryFile);
  assert.equal(fs.existsSync(temporaryFile), false);

  fs.rmSync(stateDir, { recursive: true, force: true });
});

test("thread persistence ensures canonical state directories", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-thread-dirs-"));
  const store = { stateDir };

  ensureStateDirs(store);

  assert.equal(RUNTIME_STATE_DIRS.includes("agents"), true);
  assert.equal(RUNTIME_STATE_DIRS.includes("events"), true);
  assert.equal(fs.existsSync(path.join(stateDir, "agents")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "events")), true);

  fs.rmSync(stateDir, { recursive: true, force: true });
});

test("thread persistence writes the canonical state schema with model-mounting relations", () => {
  const store = fakeStore();

  writeStateSchema(store, deps(store));

  const schemaWrite = store.writes.find((write) => write.filePath === "schema.json");
  assert.equal(schemaWrite.value.schemaVersion, "ioi.agentgres.runtime.v0");
  assert.equal(schemaWrite.value.canonicalOwner, "Agentgres");
  assert.equal(schemaWrite.value.sdkCheckpointAuthority, "cache_only");
  assert.deepEqual(schemaWrite.value.relationSchemas.runs, ["id", "agentId", "status", "objective", "mode", "createdAt", "updatedAt"]);
  assert.deepEqual(schemaWrite.value.relationSchemas.modelRoutes, ["id", "providerId"]);
});

test("thread persistence loads agents, runs, subagents, coding artifacts, and replay events", () => {
  const store = fakeStore();
  const records = {
    "agents/a.json": { id: "agent_1" },
    "runs/r.json": { id: "run_1" },
    "subagents/s.json": { subagent_id: "subagent_1" },
    "subagents/ignored.json": { role: "anonymous" },
    "artifacts/coding.json": { id: "artifact_1", schemaVersion: "ioi.coding-tool.artifact.v1" },
    "artifacts/other.json": { id: "artifact_2", schemaVersion: "other" },
  };
  const jsonFiles = {
    agents: ["agents/a.json"],
    runs: ["runs/r.json"],
    subagents: ["subagents/s.json", "subagents/ignored.json"],
    artifacts: ["artifacts/coding.json", "artifacts/other.json"],
  };

  loadStateRecords(store, {
    codingToolArtifactSchemaVersion: "ioi.coding-tool.artifact.v1",
    listJson(dir) {
      return jsonFiles[dir] ?? [];
    },
    listJsonl(dir) {
      return dir === "events" ? ["events/thread.jsonl"] : [];
    },
    readJson(file) {
      return records[file];
    },
    readJsonl(file) {
      assert.equal(file, "events/thread.jsonl");
      return [{ seq: 1 }, { seq: 2 }];
    },
  });

  assert.deepEqual(store.agents.get("agent_1"), { id: "agent_1" });
  assert.deepEqual(store.runs.get("run_1"), { id: "run_1" });
  assert.deepEqual(store.subagents.get("subagent_1"), { subagent_id: "subagent_1" });
  assert.equal(store.subagents.has("anonymous"), false);
  assert.deepEqual(store.codingArtifacts.get("artifact_1"), { id: "artifact_1", schemaVersion: "ioi.coding-tool.artifact.v1" });
  assert.equal(store.codingArtifacts.has("artifact_2"), false);
  assert.deepEqual(store.registeredEvents, [{ seq: 1 }, { seq: 2 }]);
});

test("thread persistence writes run projections without operation entries", () => {
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
  assert.deepEqual(store.operations, []);
});
