import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_AGENTGRES_COMMAND_ENV,
  RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
  RUST_AGENTGRES_STORAGE_BACKEND,
  RuntimeAgentgresAdmissionRunnerError,
  RustRuntimeAgentgresAdmissionRunner,
  createRuntimeAgentgresAdmissionRunnerFromEnv,
} from "./runtime-agentgres-admission-runner.mjs";

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

function runtimeRun() {
  return {
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
  };
}

function commitRequest() {
  return {
    schema_version: "ioi.runtime_run_state_commit.v1",
    run_id: "run_1",
    operation_kind: "run.create",
    storage_backend_ref: "storage://runtime-agentgres/local-json",
    run: runtimeRun(),
    canonical_projection: { runId: "run_1", projection: "canonical" },
  };
}

test("runtime Agentgres runner sends runtime run-state commit bridge request", () => {
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
            source: "rust_agentgres_runtime_run_state_commit_command",
            backend: RUST_AGENTGRES_STORAGE_BACKEND,
            record: {
              schema_version: "ioi.runtime_run_state_commit.v1",
              run_id: request.request.run_id,
              transition: {
                operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
                state_root_after: "sha256:after",
                resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
                transition_hash: "sha256:transition",
              },
              persistence: {
                materialization: {
                  materialization_hash: "sha256:materialization",
                },
                storage_write_set: {
                  write_set_hash: "sha256:write-set",
                  records: [{ record_path: "runs/run_1.json" }],
                },
                persistence_hash: "sha256:persistence",
              },
              commit_hash: "sha256:commit",
            },
            operation_ref: "agentgres://runtime-state/runs/run_1/operations/run.create_abcd",
            state_root_after: "sha256:after",
            resulting_head: "agentgres://runtime-state/runs/run_1/head/abcd",
            transition_hash: "sha256:transition",
            materialization_hash: "sha256:materialization",
            write_set_hash: "sha256:write-set",
            persistence_hash: "sha256:persistence",
            commit_hash: "sha256:commit",
            written_records: [{ record_path: "runs/run_1.json" }],
            evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.commitRuntimeRunState("/runtime-state", commitRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-runtime-agentgres-bridge");
  assert.equal(calls[0].request.schema_version, RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "commit_runtime_run_state");
  assert.equal(calls[0].request.backend, RUST_AGENTGRES_STORAGE_BACKEND);
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(calls[0].request.request.run_id, "run_1");
  assert.equal(Object.hasOwn(calls[0].request.request, "expected_heads"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "state_root_before"), false);
  assert.equal(Object.hasOwn(calls[0].request.request, "receipt_refs"), false);
  assert.equal(result.state_root_after, "sha256:after");
  assert.equal(result.resulting_head, "agentgres://runtime-state/runs/run_1/head/abcd");
  assert.equal(result.commit_hash, "sha256:commit");
  assert.deepEqual(result.evidence_refs, ["rust_agentgres_runtime_run_state_commit"]);
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

test("runtime Agentgres runner requires explicit runtime admission command env", () => {
  const runner = createRuntimeAgentgresAdmissionRunnerFromEnv({
    [RUNTIME_AGENTGRES_COMMAND_ENV]: "mock-runtime-bridge",
  });

  assert.equal(runner.command, "mock-runtime-bridge");
});

test("runtime Agentgres runner fails closed without command", () => {
  const runner = new RustRuntimeAgentgresAdmissionRunner();

  assert.throws(
    () => runner.commitRuntimeRunState("/runtime-state", commitRequest()),
    (error) =>
      error instanceof RuntimeAgentgresAdmissionRunnerError &&
      error.code === "runtime_agentgres_admission_bridge_unconfigured",
  );
});
