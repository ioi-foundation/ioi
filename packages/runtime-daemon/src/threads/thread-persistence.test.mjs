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
    agentCommitRequests: [],
    storageWriteAdmissions: [],
    storageWriteSetRequests: [],
    subagents: new Map(),
    commitRequests: [],
    subagentCommitRequests: [],
    persistenceEvents: [],
    persistenceRequests: [],
    rustWrites: [],
    transitionRequests: [],
    writes: [],
    canonicalProjection(runId) {
      return { runId, projection: "canonical" };
    },
    currentRunStateTransition() {
      throw new Error("legacy currentRunStateTransition path should not run");
    },
    pathFor(...segments) {
      return segments.join("/");
    },
    planRunStateTransition(request) {
      throw new Error(`legacy transition planning path should not run for ${request.run_id}`);
    },
    materializeRuntimeStateRecords(request) {
      throw new Error(`legacy materialization path should not run for ${request.run_id}`);
    },
    planRuntimeStateStorageWrites(request) {
      throw new Error(`legacy storage write-set path should not run for ${request.run_id}`);
    },
    persistRuntimeStateRecords(request) {
      throw new Error(`legacy persistence path should not run for ${request.run_id}`);
    },
    commitRuntimeRunState(request) {
      this.commitRequests.push(request);
      const receiptRefs = request.run.receipts.map((receipt) => receipt.id).filter(Boolean);
      const artifactRefs = request.run.artifacts.map((artifact) => artifact.id).filter(Boolean);
      const transition = {
        schema_version: "ioi.agentgres_runtime_state_transition.v1",
        run_id: request.run_id,
        operation_kind: request.operation_kind,
        operation_ref: `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_mock`,
        expected_heads: [`agentgres://runtime-state/runs/${request.run_id}/head/rust-derived`],
        state_root_before: "sha256:rust-derived-before",
        state_root_after: "sha256:state-after",
        resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/mock`,
        run_state_hash: "sha256:rust-run-state",
        task_state_hash: "sha256:rust-task-state",
        projection_ref: `projection://runtime/runs/${request.run_id}`,
        projection_watermark: "runtime-state:rust-derived",
        receipt_refs: receiptRefs,
        artifact_refs: artifactRefs,
        payload_refs: [`payload://runtime/runs/${request.run_id}`],
        transition_hash: "sha256:transition",
      };
      this.persistenceRequests.push(request);
      this.transitionRequests.push(transition);
      this.persistenceEvents.push({ type: "runtime_run_state_commit", runId: request.run_id });
      const files = [
        `runs/${request.run_id}.json`,
        ...(request.agent?.id ? [`agents/${request.agent.id}.json`] : []),
        `tasks/${request.run_id}.json`,
        `jobs/job_${request.run_id}.json`,
        `checklists/checklist_${request.run_id}.json`,
        ...request.run.receipts.map((receipt) => `receipts/${receipt.id}.json`),
        ...request.run.artifacts.map((artifact) => `artifacts/${artifact.id}.json`),
        `policy-decisions/${request.run_id}.json`,
        `authority-decisions/${request.run_id}.json`,
        `stop-conditions/${request.run_id}.json`,
        `scorecards/${request.run_id}.json`,
        `ledgers/${request.run_id}.json`,
        `quality/${request.run_id}.json`,
        `projections/${request.run_id}.json`,
      ];
      const records = files.map((filePath, index) => {
        const objectRef = `agentgres://runtime-state/runs/${request.run_id}/records/${filePath}`;
        const payloadRefs = [`payload://runtime/runs/${request.run_id}/records/${filePath}`];
        const admission = {
          schema_version: "ioi.storage_backend_write_admission.v1",
          storage_backend_ref: request.storage_backend_ref,
          object_ref: objectRef,
          content_hash: `sha256:content-${index}`,
          artifact_refs: [],
          payload_refs: payloadRefs,
          receipt_refs: receiptRefs,
          admission_hash: `sha256:storage-${index}`,
        };
        this.storageWriteAdmissions.push(admission);
        this.persistenceEvents.push({ type: "storage_admission", objectRef });
        this.persistenceEvents.push({ type: "rust_write_json", filePath });
        this.rustWrites.push({ filePath, objectRef });
        return {
          record_path: filePath,
          object_ref: objectRef,
          content_hash: admission.content_hash,
          artifact_refs: [],
          payload_refs: payloadRefs,
          receipt_refs: receiptRefs,
          admission,
        };
      });
      const persistence = {
        schema_version: "ioi.runtime_state_persistence.v1",
        run_id: request.run_id,
        materialization: {
          schema_version: "ioi.runtime_state_record_materialization.v1",
          run_id: request.run_id,
          records: files.map((filePath) => ({ record_path: filePath })),
          materialization_hash: `sha256:materialization-${this.persistenceRequests.length}`,
        },
        storage_write_set: {
          schema_version: "ioi.runtime_state_storage_write_set.v1",
          run_id: request.run_id,
          storage_backend_ref: request.storage_backend_ref,
          receipt_refs: receiptRefs,
          records,
          write_set_hash: `sha256:write-set-${this.persistenceRequests.length}`,
        },
        persistence_hash: `sha256:persistence-${this.persistenceRequests.length}`,
      };
      return {
        source: "rust_agentgres_runtime_run_state_commit_protocol",
        record: {
          schema_version: "ioi.runtime_run_state_commit.v1",
          run_id: request.run_id,
          transition,
          persistence,
          commit_hash: `sha256:commit-${this.persistenceRequests.length}`,
        },
        transition,
        persistence,
        operation_ref: transition.operation_ref,
        state_root_after: transition.state_root_after,
        resulting_head: transition.resulting_head,
        transition_hash: transition.transition_hash,
        materialization_hash: `sha256:materialization-${this.persistenceRequests.length}`,
        write_set_hash: `sha256:write-set-${this.persistenceRequests.length}`,
        persistence_hash: `sha256:persistence-${this.persistenceRequests.length}`,
        commit_hash: `sha256:commit-${this.persistenceRequests.length}`,
        records,
        written_records: records.map((record) => ({
          record_path: record.record_path,
          object_ref: record.object_ref,
          content_hash: record.content_hash,
          payload_refs: record.payload_refs,
          receipt_refs: record.receipt_refs,
          admission_hash: record.admission.admission_hash,
        })),
        evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
      };
    },
    commitRuntimeAgentState(request) {
      this.agentCommitRequests.push(request);
      const filePath = `agents/${request.agent_id}.json`;
      const objectRef = `agentgres://runtime-state/agents/${request.agent_id}/records/${filePath}`;
      const payloadRefs = [`payload://runtime/agents/${request.agent_id}/records/${filePath}`];
      const receiptRefs = request.agent.receipt_refs ?? request.agent.receiptRefs ?? [];
      const admission = {
        schema_version: "ioi.storage_backend_write_admission.v1",
        storage_backend_ref: request.storage_backend_ref,
        object_ref: objectRef,
        content_hash: "sha256:agent-content",
        artifact_refs: [],
        payload_refs: payloadRefs,
        receipt_refs: receiptRefs,
        admission_hash: "sha256:agent-admission",
      };
      this.storageWriteAdmissions.push(admission);
      this.persistenceEvents.push({ type: "storage_admission", objectRef });
      this.persistenceEvents.push({ type: "rust_write_json", filePath });
      this.rustWrites.push({ filePath, objectRef });
      return {
        source: "rust_agentgres_runtime_agent_state_commit_protocol",
        record: {
          schema_version: "ioi.runtime_agent_state_commit.v1",
          agent_id: request.agent_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: filePath,
            object_ref: objectRef,
            content_hash: admission.content_hash,
            artifact_refs: [],
            payload_refs: payloadRefs,
            receipt_refs: receiptRefs,
            admission,
          },
          commit_hash: "sha256:agent-commit",
        },
        agent_id: request.agent_id,
        object_ref: objectRef,
        content_hash: admission.content_hash,
        admission_hash: admission.admission_hash,
        commit_hash: "sha256:agent-commit",
        written_record: {
          record_path: filePath,
          object_ref: objectRef,
          content_hash: admission.content_hash,
          payload_refs: payloadRefs,
          receipt_refs: receiptRefs,
          admission_hash: admission.admission_hash,
        },
        evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
      };
    },
    commitRuntimeSubagentState(request) {
      this.subagentCommitRequests.push(request);
      const filePath = `subagents/${request.subagent_id}.json`;
      const objectRef = `agentgres://runtime-state/subagents/${request.subagent_id}/records/${filePath}`;
      const payloadRefs = [`payload://runtime/subagents/${request.subagent_id}/records/${filePath}`];
      const receiptRefs = request.subagent.receipt_refs ?? [];
      const admission = {
        schema_version: "ioi.storage_backend_write_admission.v1",
        storage_backend_ref: request.storage_backend_ref,
        object_ref: objectRef,
        content_hash: "sha256:subagent-content",
        artifact_refs: [],
        payload_refs: payloadRefs,
        receipt_refs: receiptRefs,
        admission_hash: "sha256:subagent-admission",
      };
      this.storageWriteAdmissions.push(admission);
      this.persistenceEvents.push({ type: "storage_admission", objectRef });
      this.persistenceEvents.push({ type: "rust_write_json", filePath });
      this.rustWrites.push({ filePath, objectRef });
      return {
        source: "rust_agentgres_runtime_subagent_state_commit_protocol",
        record: {
          schema_version: "ioi.runtime_subagent_state_commit.v1",
          subagent_id: request.subagent_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: filePath,
            object_ref: objectRef,
            content_hash: admission.content_hash,
            artifact_refs: [],
            payload_refs: payloadRefs,
            receipt_refs: receiptRefs,
            admission,
          },
          commit_hash: "sha256:subagent-commit",
        },
        subagent_id: request.subagent_id,
        object_ref: objectRef,
        content_hash: admission.content_hash,
        admission_hash: admission.admission_hash,
        commit_hash: "sha256:subagent-commit",
        written_record: {
          record_path: filePath,
          object_ref: objectRef,
          content_hash: admission.content_hash,
          payload_refs: payloadRefs,
          receipt_refs: receiptRefs,
          admission_hash: admission.admission_hash,
        },
        evidence_refs: ["rust_agentgres_runtime_subagent_state_commit"],
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

test("thread persistence commits agent records through Rust Agentgres", () => {
  const store = fakeStore();
  const agent = {
    id: "agent_1",
    status: "active",
    runtime: "local",
    updated_at: "2026-06-06T00:00:00.000Z",
    receipt_refs: ["receipt_agent"],
  };

  writeAgentRecord(store, agent, "agent.create", deps(store));

  assert.equal(store.agents.get("agent_1"), agent);
  assert.equal(store.agentCommitRequests.length, 1);
  assert.equal(store.agentCommitRequests[0].schema_version, "ioi.runtime_agent_state_commit.v1");
  assert.equal(store.agentCommitRequests[0].agent_id, "agent_1");
  assert.equal(store.agentCommitRequests[0].operation_kind, "agent.create");
  assert.deepEqual(store.agentCommitRequests[0].agent, agent);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.rustWrites.map((write) => write.filePath), ["agents/agent_1.json"]);
  assert.deepEqual(store.storageWriteAdmissions.at(-1).receipt_refs, ["receipt_agent"]);
  assert.deepEqual(store.operations, []);
});

test("thread persistence rejects agent records without stable ids", () => {
  const store = fakeStore();

  assert.throws(
    () => writeAgentRecord(store, {}, "agent.create", {
      ...deps(store),
      runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
    }),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "agent_id_required");
      assert.equal(error.details.operation_kind, "agent.create");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      return true;
    },
  );
});

test("thread persistence rejects retired agent identity aliases before Rust commit", () => {
  const store = fakeStore();
  const agent = {
    agent_id: "agent_retired",
    status: "active",
    receipt_refs: ["receipt_agent"],
  };

  assert.throws(
    () => writeAgentRecord(store, agent, "agent.create", {
      ...deps(store),
      runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
    }),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "agent_id_required");
      assert.equal(error.details.operation_kind, "agent.create");
      return true;
    },
  );
  assert.equal(store.agentCommitRequests.length, 0);
  assert.equal(store.agents.size, 0);
});

test("thread persistence does not cache agent records before Rust commit succeeds", () => {
  const store = fakeStore();
  const agent = {
    id: "agent_1",
    status: "active",
    receipt_refs: ["receipt_agent"],
  };
  store.commitRuntimeAgentState = (request) => {
    store.agentCommitRequests.push(request);
    const error = new Error("Rust Agentgres agent-state commit rejected.");
    error.code = "runtime_agent_state_commit_rejected";
    throw error;
  };

  assert.throws(
    () => writeAgentRecord(store, agent, "agent.create", deps(store)),
    (error) => {
      assert.equal(error.code, "runtime_agent_state_commit_rejected");
      return true;
    },
  );
  assert.equal(store.agentCommitRequests.length, 1);
  assert.equal(store.agents.has("agent_1"), false);
  assert.deepEqual(store.writes, []);
});

test("thread persistence commits subagent records through Rust Agentgres", () => {
  const store = fakeStore();
  const subagent = {
    subagent_id: "subagent_1",
    parent_thread_id: "thread_1",
    agent_id: "agent_1",
    lifecycle_status: "running",
    role: "research",
    updated_at: "2026-06-06T00:00:00.000Z",
    receipt_refs: ["receipt_subagent"],
  };

  writeSubagentRecord(store, subagent, "subagent.spawn", deps(store));

  assert.equal(store.subagents.get("subagent_1"), subagent);
  assert.equal(store.subagentCommitRequests.length, 1);
  assert.equal(store.subagentCommitRequests[0].schema_version, "ioi.runtime_subagent_state_commit.v1");
  assert.equal(store.subagentCommitRequests[0].subagent_id, "subagent_1");
  assert.equal(store.subagentCommitRequests[0].operation_kind, "subagent.spawn");
  assert.deepEqual(store.subagentCommitRequests[0].subagent, subagent);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.rustWrites.map((write) => write.filePath), ["subagents/subagent_1.json"]);
  assert.deepEqual(store.storageWriteAdmissions.at(-1).receipt_refs, ["receipt_subagent"]);
  assert.deepEqual(store.operations, []);
});

test("thread persistence rejects subagent records without stable ids", () => {
  const store = fakeStore();

  assert.throws(
    () => writeSubagentRecord(store, {}, "subagent.spawn", {
      ...deps(store),
      runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
    }),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "subagent_id_required");
      assert.equal(error.details.operation_kind, "subagent.spawn");
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      return true;
    },
  );
});

test("thread persistence rejects retired subagent identity aliases before Rust commit", () => {
  for (const alias of ["subagentId", "agent_id", "agentId"]) {
    const store = fakeStore();
    const subagent = {
      [alias]: "subagent_retired",
      receipt_refs: ["receipt_subagent"],
    };

    assert.throws(
      () => writeSubagentRecord(store, subagent, "subagent.spawn", {
        ...deps(store),
        runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
      }),
      (error) => {
        assert.equal(error.status, 500);
        assert.equal(error.code, "subagent_id_required");
        assert.equal(error.details.operation_kind, "subagent.spawn");
        return true;
      },
    );
    assert.equal(store.subagentCommitRequests.length, 0);
    assert.equal(store.subagents.size, 0);
  }
});

test("thread persistence does not cache subagent records before Rust commit succeeds", () => {
  const store = fakeStore();
  const subagent = {
    subagent_id: "subagent_1",
    parent_thread_id: "thread_1",
    agent_id: "agent_1",
    receipt_refs: ["receipt_subagent"],
  };
  store.commitRuntimeSubagentState = (request) => {
    store.subagentCommitRequests.push(request);
    const error = new Error("Rust Agentgres subagent-state commit rejected.");
    error.code = "runtime_subagent_state_commit_rejected";
    throw error;
  };

  assert.throws(
    () => writeSubagentRecord(store, subagent, "subagent.spawn", deps(store)),
    (error) => {
      assert.equal(error.code, "runtime_subagent_state_commit_rejected");
      return true;
    },
  );
  assert.equal(store.subagentCommitRequests.length, 1);
  assert.equal(store.subagents.has("subagent_1"), false);
  assert.deepEqual(store.writes, []);
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
    "subagents/retired-subagent-id.json": { subagentId: "subagent_retired" },
    "subagents/retired-agent-id.json": { agent_id: "subagent_agent_retired" },
    "subagents/retired-agent-camel.json": { agentId: "subagent_agent_camel_retired" },
    "artifacts/coding.json": { id: "artifact_1", schema_version: "ioi.coding-tool.artifact.v1" },
    "artifacts/retired-schema.json": { id: "artifact_retired", schemaVersion: "ioi.coding-tool.artifact.v1" },
    "artifacts/other.json": { id: "artifact_2", schema_version: "other" },
  };
  const jsonFiles = {
    agents: ["agents/a.json"],
    runs: ["runs/r.json"],
    subagents: [
      "subagents/s.json",
      "subagents/ignored.json",
      "subagents/retired-subagent-id.json",
      "subagents/retired-agent-id.json",
      "subagents/retired-agent-camel.json",
    ],
    artifacts: ["artifacts/coding.json", "artifacts/retired-schema.json", "artifacts/other.json"],
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
  assert.equal(store.subagents.has("subagent_retired"), false);
  assert.equal(store.subagents.has("subagent_agent_retired"), false);
  assert.equal(store.subagents.has("subagent_agent_camel_retired"), false);
  assert.deepEqual(store.codingArtifacts.get("artifact_1"), { id: "artifact_1", schema_version: "ioi.coding-tool.artifact.v1" });
  assert.equal(store.codingArtifacts.has("artifact_retired"), false);
  assert.equal(store.codingArtifacts.has("artifact_2"), false);
  assert.deepEqual(store.registeredEvents, [{ seq: 1 }, { seq: 2 }]);
});

test("thread persistence writes run projections without operation entries and persists records in Rust", () => {
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
  const agent = {
    id: "agent_1",
    status: "active",
    runtime: "local",
  };
  store.agents.set(agent.id, agent);

  writeRunRecord(store, run, "run.create", deps(store));

  assert.equal(store.commitRequests.length, 1);
  assert.equal(store.commitRequests[0].schema_version, "ioi.runtime_run_state_commit.v1");
  assert.equal(store.commitRequests[0].run_id, "run_1");
  assert.equal(store.commitRequests[0].operation_kind, "run.create");
  assert.equal(store.commitRequests[0].storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.deepEqual(store.commitRequests[0].run, run);
  assert.deepEqual(store.commitRequests[0].agent, agent);
  assert.deepEqual(store.commitRequests[0].canonical_projection, {
    runId: "run_1",
    projection: "canonical",
  });
  assert.equal(Object.hasOwn(store.commitRequests[0], "expected_heads"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "state_root_before"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "projection_ref"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "projection_watermark"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "receipt_refs"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "artifact_refs"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "payload_refs"), false);
  assert.equal(store.transitionRequests.length, 1);
  assert.equal(store.transitionRequests[0].schema_version, "ioi.agentgres_runtime_state_transition.v1");
  assert.deepEqual(store.transitionRequests[0].expected_heads, [
    "agentgres://runtime-state/runs/run_1/head/rust-derived",
  ]);
  assert.equal(store.transitionRequests[0].state_root_before, "sha256:rust-derived-before");
  assert.equal(store.transitionRequests[0].projection_watermark, "runtime-state:rust-derived");
  assert.deepEqual(store.transitionRequests[0].receipt_refs, ["receipt_policy", "receipt_authority"]);
  assert.deepEqual(store.transitionRequests[0].artifact_refs, ["artifact_1"]);

  assert.equal(store.materializationRequests.length, 0);
  assert.equal(store.storageWriteSetRequests.length, 0);
  assert.deepEqual(store.writes, []);

  assert.equal(store.persistenceRequests.length, 1);
  assert.equal(store.persistenceRequests[0].schema_version, "ioi.runtime_run_state_commit.v1");
  assert.equal(store.persistenceRequests[0].run_id, "run_1");
  assert.equal(store.persistenceRequests[0].storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.equal(Object.hasOwn(store.persistenceRequests[0], "receipt_refs"), false);
  assert.deepEqual(store.persistenceRequests[0].run, run);
  assert.equal(Object.hasOwn(store.persistenceRequests[0], "runtime_task"), false);
  assert.equal(Object.hasOwn(store.persistenceRequests[0], "runtime_job"), false);
  assert.equal(Object.hasOwn(store.persistenceRequests[0], "runtime_checklist"), false);
  assert.deepEqual(store.persistenceRequests[0].agent, agent);
  assert.deepEqual(store.persistenceRequests[0].canonical_projection, {
    runId: "run_1",
    projection: "canonical",
  });

  const files = store.rustWrites.map((write) => write.filePath);
  assert.deepEqual(files, [
    "runs/run_1.json",
    "agents/agent_1.json",
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
  assert.deepEqual(
    store.persistenceRequests[0].run.receipts.map((receipt) => receipt.id),
    ["receipt_policy", "receipt_authority"],
  );
  assert.equal(
    store.persistenceEvents.findIndex((event) => event.type === "runtime_run_state_commit" && event.runId === "run_1") <
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
      (event) => event.type === "rust_write_json" && event.filePath === filePath,
    );
    assert.ok(admissionIndex >= 0, `missing storage admission for ${objectRef}`);
    assert.ok(writeIndex >= 0, `missing write event for ${filePath}`);
    assert.ok(admissionIndex < writeIndex, `${objectRef} must be admitted before ${filePath} is written`);
  }
  assert.deepEqual(store.operations, []);
});

test("thread persistence fails closed when Rust omits written run-state records", () => {
  const store = fakeStore();
  store.commitRuntimeRunState = function commitRuntimeRunState(request) {
    this.commitRequests.push(request);
    return {
      source: "rust_agentgres_runtime_run_state_commit_protocol",
      record: {
        commit_hash: "sha256:commit",
        transition: {
          operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_mock",
          state_root_after: "sha256:state-after",
          resulting_head: "agentgres://runtime-state/runs/run_1/head/mock",
          transition_hash: "sha256:transition",
        },
        persistence: {
          materialization: {
            materialization_hash: "sha256:materialization",
          },
          storage_write_set: {
            records: [{ record_path: "runs/run_1.json" }],
            write_set_hash: "sha256:write-set",
          },
          persistence_hash: "sha256:persistence",
        },
      },
    };
  };

  assert.throws(
    () =>
      writeRunRecord(
        store,
        {
          id: "run_1",
          agentId: "agent_1",
          receipts: [],
          artifacts: [],
          events: [],
        },
        "run.create",
        deps(store),
      ),
    /Rust Agentgres run-state commit is missing written_records/,
  );
  assert.equal(store.commitRequests.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.rustWrites, []);
});

test("thread persistence leaves previous run-state transition lookup to Rust commit", () => {
  const store = fakeStore();
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

  assert.equal(Object.hasOwn(store.commitRequests[0], "previous_transition"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "expected_heads"), false);
  assert.equal(Object.hasOwn(store.commitRequests[0], "state_root_before"), false);
  assert.equal(
    store.transitionRequests[0].operation_ref,
    "agentgres://runtime-state/runs/run_1/operations/run.cancel_mock",
  );
});
