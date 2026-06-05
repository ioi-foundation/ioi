import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_AGENTGRES_COMMAND_SCHEMA_VERSION,
  RUNTIME_AGENTGRES_FALLBACK_COMMAND_ENV,
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
    run_state_hash: "sha256:run-state",
    task_state_hash: "sha256:task-state",
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

test("runtime Agentgres runner can reuse the generic admission command env", () => {
  const runner = createRuntimeAgentgresAdmissionRunnerFromEnv({
    [RUNTIME_AGENTGRES_FALLBACK_COMMAND_ENV]: "mock-shared-bridge",
  });

  assert.equal(runner.command, "mock-shared-bridge");
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
