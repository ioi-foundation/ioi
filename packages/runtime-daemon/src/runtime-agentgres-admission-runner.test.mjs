import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_AGENTGRES_COMMAND_ENV,
  RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
  RUST_AGENTGRES_STORAGE_BACKEND,
  RUST_RUNTIME_AGENTGRES_BACKEND,
  RuntimeAgentgresAdmissionRunnerError,
  RustRuntimeAgentgresAdmissionRunner,
  createRuntimeAgentgresAdmissionRunnerFromEnv,
} from "./runtime-agentgres-admission-runner.mjs";

function transitionRequest() {
  return {
    schema_version: "ioi.agentgres_runtime_state_transition.v1",
    run_id: "run_1",
    operation_kind: "run.create",
    expected_heads: ["agentgres://runtime-state/runs/run_1/head/0"],
    state_root_before: "sha256:before",
    run: {
      id: "run_1",
      agentId: "agent_1",
      status: "completed",
      mode: "send",
      objective: "Ship the runtime state slice",
      createdAt: "2026-06-04T00:00:00.000Z",
      updatedAt: "2026-06-04T00:00:01.000Z",
      events: [{ type: "started" }, { type: "completed" }],
      receipts: [{ id: "receipt_policy", kind: "policy_decision" }],
      artifacts: [{ id: "artifact_1", name: "result.txt", kind: "text" }],
      trace: {
        traceBundleId: "trace_bundle_1",
        taskState: { state: "done" },
        postconditions: [],
        semanticImpact: { impact: "local" },
        stopCondition: { reason: "done" },
        scorecard: { score: 1 },
        qualityLedger: { entries: [] },
      },
    },
    projection_ref: "projection://runtime/runs/run_1",
    projection_watermark: "runtime-state:1",
    receipt_refs: ["receipt_policy"],
    artifact_refs: ["artifact_1"],
    payload_refs: ["payload://runtime/runs/run_1"],
  };
}

function storageWriteRequest() {
  return {
    schema_version: "ioi.storage_backend_write_admission.v1",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
    content_hash: "sha256:run-state-json",
    artifact_refs: [],
    payload_refs: ["payload://runtime/runs/run_1/records/runs/run_1.json"],
    receipt_refs: ["receipt_policy"],
  };
}

function storageWriteSetRequest() {
  return {
    schema_version: "ioi.runtime_state_storage_write_set.v1",
    run_id: "run_1",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    receipt_refs: ["receipt_policy"],
    records: [
      {
        record_path: "runs/run_1.json",
        payload: { id: "run_1", status: "completed" },
      },
      {
        record_path: "tasks/run_1.json",
        payload: { runId: "run_1", taskState: { state: "done" } },
      },
    ],
  };
}

function materializationRequest() {
  return {
    schema_version: "ioi.runtime_state_record_materialization.v1",
    run_id: "run_1",
    run: {
      id: "run_1",
      agentId: "agent_1",
      status: "completed",
      mode: "send",
      objective: "Ship the runtime state slice",
      createdAt: "2026-06-04T00:00:00.000Z",
      updatedAt: "2026-06-04T00:00:01.000Z",
      events: [{ type: "started" }, { type: "completed" }],
      receipts: [{ id: "receipt_policy", kind: "policy_decision" }],
      artifacts: [{ id: "artifact_1", name: "result.txt", kind: "text" }],
      trace: {
        traceBundleId: "trace_bundle_1",
        taskState: { state: "done" },
        postconditions: [],
        semanticImpact: { impact: "local" },
        stopCondition: { reason: "done" },
        scorecard: { score: 1 },
        qualityLedger: { entries: [] },
      },
    },
    canonical_projection: { runId: "run_1", projection: "canonical" },
    agentgres_transition: { projection_watermark: "runtime-state:1", transition_hash: "sha256:transition" },
  };
}

function persistenceRequest() {
  return {
    schema_version: "ioi.runtime_state_persistence.v1",
    run_id: "run_1",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    receipt_refs: ["receipt_policy"],
    run: materializationRequest().run,
    canonical_projection: { runId: "run_1", projection: "canonical" },
    agentgres_transition: {
      operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
      state_root_after: "sha256:after",
      resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
      projection_watermark: "runtime-state:1",
      transition_hash: "sha256:transition",
    },
  };
}

test("runtime Agentgres runner sends run-state transition bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_runtime_agentgres_transition_command",
            backend: RUST_RUNTIME_AGENTGRES_BACKEND,
            record: {
              ...request.request,
              operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
              state_root_after: "sha256:after",
              resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
              transition_hash: "sha256:transition",
            },
            operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
            state_root_after: "sha256:after",
            resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
            transition_hash: "sha256:transition",
            evidence_refs: ["rust_agentgres_runtime_state_transition"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planRunStateTransition(transitionRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_runtime_run_state_transition");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(result.state_root_after, "sha256:after");
  assert.equal(result.resulting_head, "agentgres://runtime-state/runs/run_1/head/abcd");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_state_transition"]);
});

test("runtime Agentgres runner sends storage write admission bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_storage_write_admission_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              ...request.request,
              admission_hash: "sha256:storage-admission",
            },
            admission_hash: "sha256:storage-admission",
            evidence_refs: ["rust_agentgres_storage_write_admission"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitStorageBackendWrite(storageWriteRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_storage_backend_write");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.storage_backend_ref, "storage://runtime-agentgres/local-json");
  assert.equal(result.admission_hash, "sha256:storage-admission");
  assert.equal(result.object_ref, "agentgres://runtime-state/runs/run_1/records/runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_storage_write_admission"]);
});

test("runtime Agentgres runner sends runtime-state storage write-set bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_state_storage_write_set_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              ...request.request,
              records: request.request.records.map((record) => ({
                record_path: record.record_path,
                object_ref: `agentgres://runtime-state/runs/run_1/records/${record.record_path}`,
                content_hash: "sha256:content",
                artifact_refs: [],
                payload_refs: [`payload://runtime/runs/run_1/records/${record.record_path}`],
                receipt_refs: request.request.receipt_refs,
                admission: {
                  schema_version: "ioi.storage_backend_write_admission.v1",
                  storage_backend_ref: request.request.storage_backend_ref,
                  object_ref: `agentgres://runtime-state/runs/run_1/records/${record.record_path}`,
                  content_hash: "sha256:content",
                  artifact_refs: [],
                  payload_refs: [`payload://runtime/runs/run_1/records/${record.record_path}`],
                  receipt_refs: request.request.receipt_refs,
                  admission_hash: "sha256:admission",
                },
              })),
              write_set_hash: "sha256:write-set",
            },
            write_set_hash: "sha256:write-set",
            records: [
              {
                record_path: "runs/run_1.json",
                object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
              },
            ],
            evidence_refs: ["rust_agentgres_runtime_state_storage_write_set"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.planRuntimeStateStorageWrites(storageWriteSetRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "plan_runtime_state_storage_writes");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.request.records.length, 2);
  assert.equal(result.write_set_hash, "sha256:write-set");
  assert.equal(result.records[0].record_path, "runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_state_storage_write_set"]);
});

test("runtime Agentgres runner sends runtime-state record materialization bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_state_record_materialization_command",
            backend: RUST_RUNTIME_AGENTGRES_BACKEND,
            record: {
              ...request.request,
              records: [
                { record_path: "runs/run_1.json", payload: request.request.run },
                { record_path: "tasks/run_1.json", payload: { runId: "run_1" } },
              ],
              materialization_hash: "sha256:materialization",
            },
            records: [
              { record_path: "runs/run_1.json", payload: request.request.run },
              { record_path: "tasks/run_1.json", payload: { runId: "run_1" } },
            ],
            materialization_hash: "sha256:materialization",
            evidence_refs: ["rust_agentgres_runtime_state_record_materialization"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.materializeRuntimeStateRecords(materializationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "materialize_runtime_state_records");
  assert.equal(calls[0].request.backend, RUST_RUNTIME_AGENTGRES_BACKEND);
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(result.materialization_hash, "sha256:materialization");
  assert.equal(result.records[0].record_path, "runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_state_record_materialization"]);
});

test("runtime Agentgres runner sends runtime-state persistence bridge request", () => {
  const calls = [];
  const runner = new RustRuntimeAgentgresAdmissionRunner({
    command: "mock-runtime-agentgres-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_agentgres_runtime_state_persistence_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_state_persistence.v1",
              run_id: request.request.run_id,
              materialization: {
                materialization_hash: "sha256:materialization",
                records: [{ record_path: "runs/run_1.json" }],
              },
              storage_write_set: {
                write_set_hash: "sha256:write-set",
                records: [{ record_path: "runs/run_1.json" }],
              },
              persistence_hash: "sha256:persistence",
            },
            materialization_hash: "sha256:materialization",
            write_set_hash: "sha256:write-set",
            persistence_hash: "sha256:persistence",
            records: [{ record_path: "runs/run_1.json" }],
            written_records: [
              {
                record_path: "runs/run_1.json",
                object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                content_hash: "sha256:content",
              },
            ],
            evidence_refs: ["rust_agentgres_runtime_state_persistence"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.persistRuntimeStateRecords("/runtime-state", persistenceRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "persist_runtime_state_records");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.schema_version, "ioi.runtime_state_persistence.v1");
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(result.persistence_hash, "sha256:persistence");
  assert.equal(result.materialization_hash, "sha256:materialization");
  assert.equal(result.write_set_hash, "sha256:write-set");
  assert.equal(result.written_records[0].record_path, "runs/run_1.json");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_state_persistence"]);
});

test("runtime Agentgres runner requires explicit runtime admission command env", () => {
  const runner = createRuntimeAgentgresAdmissionRunnerFromEnv({
    [RUNTIME_AGENTGRES_COMMAND_ENV]: "mock-runtime-bridge",
  });

  assert.equal(runner.command, "mock-runtime-bridge");
});

test("runtime Agentgres runner fails closed without command", () => {
  const runner = new RustRuntimeAgentgresAdmissionRunner();

  assert.throws(
    () => runner.planRunStateTransition(transitionRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_admission_bridge_unconfigured",
  );
});
