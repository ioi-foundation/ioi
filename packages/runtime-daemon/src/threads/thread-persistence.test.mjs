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
    materializationRequests: [],
    registeredEvents: [],
    runs: new Map(),
    schemaVersion: "ioi.agentgres.runtime.v0",
    storageWriteAdmissions: [],
    storageWriteSetRequests: [],
    subagents: new Map(),
    persistenceEvents: [],
    transitionRequests: [],
    writes: [],
    canonicalProjection(runId) {
      return { runId, projection: "canonical" };
    },
    currentRunStateTransition() {
      return null;
    },
    pathFor(...segments) {
      return segments.join("/");
    },
    planRunStateTransition(request) {
      this.transitionRequests.push(request);
      return {
        source: "rust_runtime_agentgres_mock",
        record: {
          schema_version: "ioi.agentgres_runtime_state_transition.v1",
          run_id: request.run_id,
          operation_kind: request.operation_kind,
          operation_ref: `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_mock`,
          expected_heads: request.expected_heads,
          state_root_before: request.state_root_before,
          state_root_after: "sha256:state-after",
          resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/mock`,
          run_state_hash: "sha256:rust-run-state",
          task_state_hash: "sha256:rust-task-state",
          projection_ref: request.projection_ref,
          projection_watermark: request.projection_watermark,
          receipt_refs: request.receipt_refs,
          artifact_refs: request.artifact_refs,
          payload_refs: request.payload_refs,
          transition_hash: "sha256:transition",
        },
        operation_ref: `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_mock`,
        expected_heads: request.expected_heads,
        state_root_before: request.state_root_before,
        state_root_after: "sha256:state-after",
        resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/mock`,
        projection_watermark: request.projection_watermark,
        transition_hash: "sha256:transition",
        evidence_refs: ["rust_agentgres_runtime_state_transition"],
      };
    },
    materializeRuntimeStateRecords(request) {
      this.materializationRequests.push(request);
      this.persistenceEvents.push({ type: "record_materialization", runId: request.run_id });
      const runtimeTask = request.run.runtimeTask ?? {
        schemaVersion: "ioi.agent-runtime.task-record.v1",
        object: "ioi.runtime_task",
        taskId: `task_${request.run_id}`,
        runId: request.run_id,
        agentId: request.run.agentId,
        threadId: "thread_1",
        turnId: "turn_1",
        status: "completed",
        mode: request.run.mode,
        taskFamily: "local_daemon_agentgres",
        selectedStrategy: "local_daemon_agentgres_execution",
      };
      const runtimeJob = request.run.runtimeJob ?? {
        schemaVersion: "ioi.agent-runtime.job-record.v1",
        object: "ioi.runtime_job",
        jobId: `job_${request.run_id}`,
        taskId: runtimeTask.taskId,
        runId: request.run_id,
        agentId: request.run.agentId,
        status: "completed",
        eventCount: request.run.events.length,
      };
      const runtimeChecklist = request.run.runtimeChecklist ?? {
        schemaVersion: "ioi.agent-runtime.checklist-record.v1",
        object: "ioi.runtime_checklist",
        checklistId: `checklist_${request.run_id}`,
        taskId: runtimeTask.taskId,
        jobId: runtimeJob.jobId,
        runId: request.run_id,
        agentId: request.run.agentId,
        status: "completed",
        itemCount: 6,
        completedItemCount: 6,
      };
      const records = [
        { record_path: `runs/${request.run_id}.json`, payload: request.run, artifact_refs: [], payload_refs: [] },
        {
          record_path: `tasks/${request.run_id}.json`,
          payload: {
            runId: request.run_id,
            agentId: request.run.agentId,
            runtimeTask,
            runtimeChecklist,
            taskState: request.run.trace.taskState,
            postconditions: request.run.trace.postconditions,
            semanticImpact: request.run.trace.semanticImpact,
            projectionWatermark: request.agentgres_transition.projection_watermark,
            agentgresTransition: request.agentgres_transition,
          },
          artifact_refs: [],
          payload_refs: [],
        },
        { record_path: `jobs/${runtimeJob.jobId}.json`, payload: runtimeJob, artifact_refs: [], payload_refs: [] },
        {
          record_path: `checklists/${runtimeChecklist.checklistId}.json`,
          payload: runtimeChecklist,
          artifact_refs: [],
          payload_refs: [],
        },
        ...request.run.receipts.map((receipt) => ({
          record_path: `receipts/${receipt.id}.json`,
          payload: { runId: request.run_id, ...receipt },
          artifact_refs: [],
          payload_refs: [],
        })),
        ...request.run.artifacts.map((artifact) => ({
          record_path: `artifacts/${artifact.id}.json`,
          payload: artifact,
          artifact_refs: [],
          payload_refs: [],
        })),
        {
          record_path: `policy-decisions/${request.run_id}.json`,
          payload: {
            runId: request.run_id,
            decision: "allowed",
            rationale: "Local daemon run stayed inside bounded local/private runtime contract.",
            primitiveCapabilities: ["prim:model.invoke"],
            authorityScopes: [],
            receiptId: request.run.receipts.find((receipt) => receipt.kind === "policy_decision")?.id,
          },
          artifact_refs: [],
          payload_refs: [],
        },
        {
          record_path: `authority-decisions/${request.run_id}.json`,
          payload: {
            runId: request.run_id,
            decision: "allowed",
            authorityScopes: [],
            walletLayer: "wallet.network",
            receiptId: request.run.receipts.find((receipt) => receipt.kind === "authority_decision")?.id,
          },
          artifact_refs: [],
          payload_refs: [],
        },
        { record_path: `stop-conditions/${request.run_id}.json`, payload: request.run.trace.stopCondition, artifact_refs: [], payload_refs: [] },
        { record_path: `scorecards/${request.run_id}.json`, payload: request.run.trace.scorecard, artifact_refs: [], payload_refs: [] },
        { record_path: `ledgers/${request.run_id}.json`, payload: request.run.trace.qualityLedger, artifact_refs: [], payload_refs: [] },
        {
          record_path: `quality/${request.run_id}.json`,
          payload: {
            runId: request.run_id,
            scorecard: request.run.trace.scorecard,
            qualityLedger: request.run.trace.qualityLedger,
            stopCondition: request.run.trace.stopCondition,
            verifierIndependencePolicy: {
              sameModelAllowed: false,
              evidenceOnlyMode: true,
              humanReviewThreshold: "high_risk",
            },
          },
          artifact_refs: [],
          payload_refs: [],
        },
        {
          record_path: `projections/${request.run_id}.json`,
          payload: {
            ...request.canonical_projection,
            agentgresTransition: request.agentgres_transition,
          },
          artifact_refs: [],
          payload_refs: [],
        },
      ];
      return {
        source: "rust_agentgres_runtime_state_record_materialization_command",
        record: {
          schema_version: "ioi.runtime_state_record_materialization.v1",
          run_id: request.run_id,
          records,
          materialization_hash: `sha256:materialization-${this.materializationRequests.length}`,
        },
        records,
        materialization_hash: `sha256:materialization-${this.materializationRequests.length}`,
        evidence_refs: ["rust_agentgres_runtime_state_record_materialization"],
      };
    },
    planRuntimeStateStorageWrites(request) {
      this.storageWriteSetRequests.push(request);
      const records = request.records.map((record, index) => {
        const objectRef = `agentgres://runtime-state/runs/${request.run_id}/records/${record.record_path}`;
        const payloadRefs = [`payload://runtime/runs/${request.run_id}/records/${record.record_path}`];
        const admission = {
          schema_version: "ioi.storage_backend_write_admission.v1",
          storage_backend_ref: request.storage_backend_ref,
          object_ref: objectRef,
          content_hash: `sha256:content-${index}`,
          artifact_refs: record.artifact_refs,
          payload_refs: payloadRefs,
          receipt_refs: request.receipt_refs,
          admission_hash: `sha256:storage-${index}`,
        };
        this.storageWriteAdmissions.push(admission);
        this.persistenceEvents.push({ type: "storage_admission", objectRef });
        return {
          record_path: record.record_path,
          object_ref: objectRef,
          content_hash: admission.content_hash,
          artifact_refs: record.artifact_refs,
          payload_refs: payloadRefs,
          receipt_refs: request.receipt_refs,
          admission,
        };
      });
      return {
        source: "rust_agentgres_runtime_state_storage_write_set_command",
        record: {
          schema_version: "ioi.runtime_state_storage_write_set.v1",
          run_id: request.run_id,
          storage_backend_ref: request.storage_backend_ref,
          receipt_refs: request.receipt_refs,
          records,
          write_set_hash: `sha256:write-set-${this.storageWriteSetRequests.length}`,
        },
        write_set_hash: `sha256:write-set-${this.storageWriteSetRequests.length}`,
        storage_backend_ref: request.storage_backend_ref,
        records,
        storage_admissions: records.map((record) => record.admission),
        evidence_refs: ["rust_agentgres_runtime_state_storage_write_set"],
      };
    },
    registerRuntimeEvent(record) {
      this.registeredEvents.push(record);
    },
  };
}

function deps(store) {
  return {
    writeJson(filePath, value) {
      store.persistenceEvents.push({ type: "write_json", filePath });
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

test("thread persistence writes run projections without operation entries and materializes records and plans storage write set in Rust", () => {
  const store = fakeStore();
  const run = {
    id: "run_1",
    agentId: "agent_1",
    status: "completed",
    mode: "send",
    objective: "Ship the runtime state slice",
    createdAt: "2026-06-04T00:00:00.000Z",
    updatedAt: "2026-06-04T00:00:01.000Z",
    events: [{ type: "started" }, { type: "completed" }],
    receipts: [
      { id: "receipt_policy", kind: "policy_decision" },
      { id: "receipt_authority", kind: "authority_decision" },
    ],
    artifacts: [{ id: "artifact_1", name: "result.txt", kind: "text" }],
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

  assert.equal(store.transitionRequests.length, 1);
  assert.equal(store.transitionRequests[0].schema_version, "ioi.agentgres_runtime_state_transition.v1");
  assert.equal(store.transitionRequests[0].run_id, "run_1");
  assert.equal(store.transitionRequests[0].operation_kind, "run.create");
  assert.deepEqual(store.transitionRequests[0].expected_heads, [
    "agentgres://runtime-state/runs/run_1/head/0",
  ]);
  assert.match(store.transitionRequests[0].state_root_before, /^sha256:/);
  assert.deepEqual(store.transitionRequests[0].run, run);
  assert.equal(Object.hasOwn(store.transitionRequests[0], "run_state_hash"), false);
  assert.equal(Object.hasOwn(store.transitionRequests[0], "task_state_hash"), false);
  assert.equal(store.transitionRequests[0].projection_watermark, "runtime-state:1");
  assert.deepEqual(store.transitionRequests[0].receipt_refs, ["receipt_policy", "receipt_authority"]);
  assert.deepEqual(store.transitionRequests[0].artifact_refs, ["artifact_1"]);

  assert.equal(store.materializationRequests.length, 1);
  assert.equal(store.materializationRequests[0].schema_version, "ioi.runtime_state_record_materialization.v1");
  assert.equal(store.materializationRequests[0].run_id, "run_1");
  assert.deepEqual(store.materializationRequests[0].run, run);
  assert.equal(Object.hasOwn(store.materializationRequests[0], "runtime_task"), false);
  assert.equal(Object.hasOwn(store.materializationRequests[0], "runtime_job"), false);
  assert.equal(Object.hasOwn(store.materializationRequests[0], "runtime_checklist"), false);
  assert.deepEqual(store.materializationRequests[0].canonical_projection, {
    runId: "run_1",
    projection: "canonical",
  });
  assert.equal(
    store.materializationRequests[0].agentgres_transition.operation_ref,
    "agentgres://runtime-state/runs/run_1/operations/run.create_mock",
  );

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
  assert.equal(store.storageWriteSetRequests.length, 1);
  assert.equal(store.storageWriteSetRequests[0].schema_version, "ioi.runtime_state_storage_write_set.v1");
  assert.equal(store.storageWriteSetRequests[0].run_id, "run_1");
  assert.equal(store.storageWriteSetRequests[0].storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.deepEqual(store.storageWriteSetRequests[0].receipt_refs, ["receipt_policy", "receipt_authority"]);
  assert.deepEqual(
    store.storageWriteSetRequests[0].records.map((record) => record.record_path),
    files,
  );
  assert.deepEqual(store.storageWriteSetRequests[0].records[0].payload, run);
  assert.deepEqual(
    store.materializationRequests[0].run.receipts.map((receipt) => receipt.id),
    ["receipt_policy", "receipt_authority"],
  );
  assert.equal(
    store.persistenceEvents.findIndex((event) => event.type === "record_materialization" && event.runId === "run_1") <
      store.persistenceEvents.findIndex((event) => event.type === "storage_admission"),
    true,
  );
  assert.equal(store.storageWriteAdmissions.length, files.length);
  assert.deepEqual(
    store.storageWriteAdmissions.map((admission) =>
      admission.object_ref.replace("agentgres://runtime-state/runs/run_1/records/", ""),
    ),
    files,
  );
  for (const admission of store.storageWriteAdmissions) {
    assert.equal(admission.schema_version, "ioi.storage_backend_write_admission.v1");
    assert.equal(admission.storage_backend_ref, "storage://runtime-agentgres/local-json");
    assert.match(admission.content_hash, /^sha256:/);
    assert.deepEqual(admission.receipt_refs, ["receipt_policy", "receipt_authority"]);
    assert.equal(admission.payload_refs.length, 1);
    assert.match(admission.payload_refs[0], /^payload:\/\/runtime\/runs\/run_1\/records\//);
  }
  for (const filePath of files) {
    const objectRef = `agentgres://runtime-state/runs/run_1/records/${filePath}`;
    const admissionIndex = store.persistenceEvents.findIndex(
      (event) => event.type === "storage_admission" && event.objectRef === objectRef,
    );
    const writeIndex = store.persistenceEvents.findIndex(
      (event) => event.type === "write_json" && event.filePath === filePath,
    );
    assert.ok(admissionIndex >= 0, `missing storage admission for ${objectRef}`);
    assert.ok(writeIndex >= 0, `missing write event for ${filePath}`);
    assert.ok(admissionIndex < writeIndex, `${objectRef} must be admitted before ${filePath} is written`);
  }
  const taskWrite = store.writes.find((write) => write.filePath === "tasks/run_1.json").value;
  assert.equal(taskWrite.runId, "run_1");
  assert.equal(taskWrite.agentId, "agent_1");
  assert.equal(taskWrite.runtimeTask.schemaVersion, "ioi.agent-runtime.task-record.v1");
  assert.equal(taskWrite.runtimeTask.taskId, "task_run_1");
  assert.equal(taskWrite.runtimeChecklist.schemaVersion, "ioi.agent-runtime.checklist-record.v1");
  assert.equal(taskWrite.runtimeChecklist.checklistId, "checklist_run_1");
  assert.deepEqual(taskWrite.taskState, { state: "done" });
  assert.deepEqual(taskWrite.postconditions, [{ id: "postcondition_1" }]);
  assert.deepEqual(taskWrite.semanticImpact, { impact: "local" });
  assert.equal(taskWrite.projectionWatermark, "runtime-state:1");
  assert.deepEqual(taskWrite.agentgresTransition, {
    schema_version: "ioi.agentgres_runtime_state_transition.v1",
    operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_mock",
    expected_heads: ["agentgres://runtime-state/runs/run_1/head/0"],
    state_root_before: store.transitionRequests[0].state_root_before,
    state_root_after: "sha256:state-after",
    resulting_head: "agentgres://runtime-state/runs/run_1/head/mock",
    projection_watermark: "runtime-state:1",
    transition_hash: "sha256:transition",
    evidence_refs: ["rust_agentgres_runtime_state_transition"],
    record: {
      schema_version: "ioi.agentgres_runtime_state_transition.v1",
      run_id: "run_1",
      operation_kind: "run.create",
      operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_mock",
      expected_heads: ["agentgres://runtime-state/runs/run_1/head/0"],
      state_root_before: store.transitionRequests[0].state_root_before,
      state_root_after: "sha256:state-after",
      resulting_head: "agentgres://runtime-state/runs/run_1/head/mock",
      projection_watermark: "runtime-state:1",
      transition_hash: "sha256:transition",
      run_state_hash: "sha256:rust-run-state",
      task_state_hash: "sha256:rust-task-state",
      projection_ref: "projection://runtime/runs/run_1",
      projection_watermark: "runtime-state:1",
      receipt_refs: ["receipt_policy", "receipt_authority"],
      artifact_refs: ["artifact_1"],
      payload_refs: ["payload://runtime/runs/run_1"],
      transition_hash: "sha256:transition",
    },
  });
  assert.deepEqual(store.writes.find((write) => write.filePath === "projections/run_1.json").value, {
    runId: "run_1",
    projection: "canonical",
    agentgresTransition: store.writes.find((write) => write.filePath === "tasks/run_1.json").value.agentgresTransition,
  });
  assert.deepEqual(store.operations, []);
});

test("thread persistence chains run-state transitions from the previous persisted head", () => {
  const store = fakeStore();
  store.currentRunStateTransition = () => ({
    state_root_after: "sha256:previous-state-root",
    resulting_head: "agentgres://runtime-state/runs/run_1/head/previous",
  });
  const run = {
    id: "run_1",
    agentId: "agent_1",
    status: "canceled",
    events: [{ type: "started" }, { type: "canceled" }],
    receipts: [{ id: "receipt_cancel", kind: "run_cancel" }],
    artifacts: [],
    trace: {
      taskState: { state: "canceled" },
      postconditions: [],
      semanticImpact: { impact: "local" },
      stopCondition: { reason: "operator_cancel" },
      scorecard: { score: 1 },
      qualityLedger: { entries: [] },
      traceBundleId: "trace_bundle_1",
    },
  };

  writeRunRecord(store, run, "run.cancel", deps(store));

  assert.deepEqual(store.transitionRequests[0].expected_heads, [
    "agentgres://runtime-state/runs/run_1/head/previous",
  ]);
  assert.equal(store.transitionRequests[0].state_root_before, "sha256:previous-state-root");
  assert.equal(
    store.writes.find((write) => write.filePath === "tasks/run_1.json").value.agentgresTransition.operation_ref,
    "agentgres://runtime-state/runs/run_1/operations/run.cancel_mock",
  );
});
