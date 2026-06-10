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
});

test("mounted runtime-engine requests ignore retired camelCase aliases", () => {
  const state = fakeState();

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
});
