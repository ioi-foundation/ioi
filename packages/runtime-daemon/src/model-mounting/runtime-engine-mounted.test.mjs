import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function callMounted(method, state, ...args) {
  return ModelMountingState.prototype[method].call(state, ...args);
}

function fakeState() {
  return {
    receipts: [],
    recordStateCommits: [],
    projections: 0,
    runtimeEngineRequiredRequests: [],
    modelMountAdmissionRunner: {
      planRuntimeEngineRequired: (request) => {
        const details = {
          operation: request.operation,
          ...request.details,
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.runtime_engine",
          source: request.source,
          evidence_refs: request.evidence_refs,
        };
        fakeState.current.runtimeEngineRequiredRequests.push(request);
        return {
          source: "rust_model_mount_runtime_engine_required_command",
          backend: "rust_model_mount_runtime_engine_required",
          status: "rust_core_required",
          status_code: 501,
          code: "model_mount_runtime_engine_rust_core_required",
          message:
            "Runtime-engine mutation facade requires Rust daemon-core model_mount runtime-engine ownership.",
          rust_core_boundary: "model_mount.runtime_engine",
          operation_kind: request.operation_kind,
          details,
          evidence_refs: request.evidence_refs,
          record: {
            schema_version: "ioi.model_mount.runtime_engine_required_result.v1",
            object: "ioi.model_mount_runtime_engine_required",
            status: "rust_core_required",
            status_code: 501,
            code: "model_mount_runtime_engine_rust_core_required",
            message:
              "Runtime-engine mutation facade requires Rust daemon-core model_mount runtime-engine ownership.",
            rust_core_boundary: "model_mount.runtime_engine",
            operation: request.operation,
            operation_kind: request.operation_kind,
            source: request.source,
            evidence_refs: request.evidence_refs,
            details,
            generated_at: "rust_model_mount_core",
          },
        };
      },
    },
    runtimeEngineRequired(operationKind, details = {}) {
      return ModelMountingState.prototype.runtimeEngineRequired.call(this, operationKind, details);
    },
  };
}

function assertRuntimeEngineRustCoreRequired(error, operationKind, details = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_runtime_engine_rust_core_required");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.runtime_engine");
  assert.deepEqual(error.details.evidence_refs, [
    "public_runtime_engine_js_facade_retired",
    "rust_daemon_core_runtime_engine_required",
    "agentgres_runtime_engine_truth_required",
  ]);
  for (const [key, value] of Object.entries(details)) {
    assert.equal(error.details[key], value);
  }
  assert.equal(Object.hasOwn(error.details, "engineId"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
  return true;
}

test("mounted runtime-engine mutation facade fails closed until Rust core owns it", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () => callMounted("selectRuntimeEngine", state, { engine_id: "backend.llama-cpp" }),
    (error) =>
      assertRuntimeEngineRustCoreRequired(error, "model_mount.runtime_preference.write", {
        engine_id: "backend.llama-cpp",
      }),
  );
  assert.throws(
    () =>
      callMounted("updateRuntimeEngine", state, "backend.llama-cpp", {
        default_load_options: { gpu_layers: 4 },
      }),
    (error) =>
      assertRuntimeEngineRustCoreRequired(error, "model_mount.runtime_engine_profile.write", {
        engine_id: "backend.llama-cpp",
      }),
  );
  assert.throws(
    () => callMounted("removeRuntimeEngineOverride", state, "backend.llama-cpp"),
    (error) =>
      assertRuntimeEngineRustCoreRequired(error, "model_mount.runtime_engine_profile.delete", {
        engine_id: "backend.llama-cpp",
      }),
  );

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
  assert.equal(state.runtimeEngineRequiredRequests.length, 3);
  assert.equal(state.runtimeEngineRequiredRequests[0].schema_version, "ioi.model_mount.runtime_engine_required.v1");
  assert.equal(state.runtimeEngineRequiredRequests[0].operation, "model_mount.runtime_engine");
  assert.equal(state.runtimeEngineRequiredRequests[0].operation_kind, "model_mount.runtime_preference.write");
  assert.equal(state.runtimeEngineRequiredRequests[0].details.engine_id, "backend.llama-cpp");
  assert.equal(state.runtimeEngineRequiredRequests[1].operation_kind, "model_mount.runtime_engine_profile.write");
  assert.equal(state.runtimeEngineRequiredRequests[2].operation_kind, "model_mount.runtime_engine_profile.delete");
  assert.equal(Object.hasOwn(state.runtimeEngineRequiredRequests[0].details, "engineId"), false);
  assert.equal(Object.hasOwn(state.runtimeEngineRequiredRequests[0], "operationKind"), false);
});

test("mounted runtime-engine requests ignore retired camelCase aliases", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () =>
      callMounted("selectRuntimeEngine", state, {
        engineId: "backend.llama-cpp",
        defaultLoadOptions: { gpu: "retired" },
        operatorLabel: "Retired label",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "runtime");
      assert.equal(error.details.field, "engine_id");
      assert.equal(Object.hasOwn(error.details, "engineId"), false);
      assert.equal(Object.hasOwn(error.details, "defaultLoadOptions"), false);
      assert.equal(Object.hasOwn(error.details, "operatorLabel"), false);
      return true;
    },
  );

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
  assert.deepEqual(state.runtimeEngineRequiredRequests, []);
});
