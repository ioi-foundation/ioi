import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function callMounted(method, state, ...args) {
  return ModelMountingState.prototype[method].call(state, ...args);
}

function fakeState() {
  const state = {
    runtimeEnginePlans: [],
    recordStateCommits: [],
    nowIso: () => "2026-06-13T12:00:00.000Z",
    planRuntimeEngine(request) {
      state.runtimeEnginePlans.push(request);
      const recordId = `runtime-engine-control:${state.runtimeEnginePlans.length}`;
      return {
        source: "rust_daemon_core.model_mount.runtime_engine",
        schema_version: "ioi.model_mount.runtime_engine_plan.v1",
        object: "ioi.model_mount_runtime_engine_plan",
        status: "planned",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: request.operation_kind,
        source_request: request.source,
        record_dir: "runtime-engine-controls",
        record_id: recordId,
        record: {
          id: recordId,
          object: "ioi.model_mount_runtime_engine_record",
          engine_id: request.engine_id,
          rust_core_boundary: "model_mount.runtime_engine",
          operation_kind: request.operation_kind,
          public_response: {
            object: "ioi.model_mount_runtime_engine",
            status: "planned",
            engine_id: request.engine_id,
            operation_kind: request.operation_kind,
          },
          evidence_refs: [
            "public_runtime_engine_js_facade_retired",
            "rust_daemon_core_runtime_engine",
            "agentgres_runtime_engine_truth_required",
          ],
        },
        public_response: {
          object: "ioi.model_mount_runtime_engine",
          status: "planned",
          engine_id: request.engine_id,
          operation_kind: request.operation_kind,
          js_preference_write: false,
          js_profile_write: false,
          js_projection_write: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_runtime_engine_js_facade_retired",
          "rust_daemon_core_runtime_engine",
          "agentgres_runtime_engine_truth_required",
        ],
        control_hash: `sha256:${request.operation_kind.replaceAll(".", "_")}`,
      };
    },
    commitRuntimeModelMountRecordState(request) {
      state.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `runtime-engine-controls/${request.record_id}`,
        content_hash: "sha256:content",
        admission_hash: "sha256:admission",
        commit_hash: "sha256:commit",
        written_record: request.record,
        storage_record: {
          object_ref: `runtime-engine-controls/${request.record_id}`,
          content_hash: "sha256:content",
          admission: { admission_hash: "sha256:admission" },
        },
      };
    },
  };
  return state;
}

function fakeStateWithoutPlanner() {
  const state = fakeState();
  delete state.planRuntimeEngine;
  return state;
}

function assertRuntimeEngineRustCoreRequired(error, operationKind, details = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_runtime_engine_rust_core_required");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.runtime_engine");
  assert.deepEqual(error.details.evidence_refs, [
    "public_runtime_engine_js_facade_retired",
    "rust_daemon_core_runtime_engine",
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

test("mounted runtime-engine mutation facades commit Rust-authored records", () => {
  const state = fakeState();

  const selected = callMounted("selectRuntimeEngine", state, {
    engine_id: "backend.llama-cpp",
    engineId: "backend.retired",
    defaultLoadOptions: { gpu: "retired" },
    operatorLabel: "Retired label",
    receipt_refs: ["receipt://runtime-engine"],
  });
  const updated = callMounted("updateRuntimeEngine", state, "backend.llama-cpp", {
    default_load_options: { gpu_layers: 4 },
    defaultLoadOptions: { gpu: "retired" },
    operator_label: "Native local",
    operatorLabel: "Retired label",
    receipt_id: "receipt://runtime-profile",
  });
  const removed = callMounted("removeRuntimeEngineOverride", state, "backend.llama-cpp");

  for (const response of [selected, updated, removed]) {
    assert.equal(response.rust_core_boundary, "model_mount.runtime_engine");
    assert.equal(response.evidence_refs.includes("rust_daemon_core_runtime_engine"), true);
    assert.equal(response.commit.record_id, response.record_id);
    assert.equal(response.js_preference_write, false);
    assert.equal(response.js_profile_write, false);
    assert.equal(response.js_projection_write, false);
  }

  assert.equal(selected.operation_kind, "model_mount.runtime_preference.write");
  assert.equal(updated.operation_kind, "model_mount.runtime_engine_profile.write");
  assert.equal(removed.operation_kind, "model_mount.runtime_engine_profile.delete");
  assert.equal(state.runtimeEnginePlans.length, 3);
  assert.equal(state.recordStateCommits.length, 3);
  assert.equal(state.runtimeEnginePlans[0].schema_version, "ioi.model_mount.runtime_engine.v1");
  assert.equal(state.runtimeEnginePlans[0].operation_kind, "model_mount.runtime_preference.write");
  assert.equal(state.runtimeEnginePlans[0].engine_id, "backend.llama-cpp");
  assert.equal(state.runtimeEnginePlans[1].operation_kind, "model_mount.runtime_engine_profile.write");
  assert.deepEqual(state.runtimeEnginePlans[1].body.default_load_options, { gpu_layers: 4 });
  assert.equal(state.runtimeEnginePlans[1].body.operator_label, "Native local");
  assert.equal(state.runtimeEnginePlans[2].operation_kind, "model_mount.runtime_engine_profile.delete");
  assert.equal(state.runtimeEnginePlans[0].receipt_refs[0], "receipt://runtime-engine");
  assert.equal(state.runtimeEnginePlans[1].receipt_refs[0], "receipt://runtime-profile");
  assert.equal(Object.hasOwn(state.runtimeEnginePlans[0], "operationKind"), false);
  assert.equal(Object.hasOwn(state.runtimeEnginePlans[0].body, "engineId"), false);
  assert.equal(Object.hasOwn(state.runtimeEnginePlans[1].body, "defaultLoadOptions"), false);
  assert.equal(Object.hasOwn(state.runtimeEnginePlans[1].body, "operatorLabel"), false);
  assert.equal(state.recordStateCommits[0].record_dir, "runtime-engine-controls");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.runtime_preference.write");
});

test("mounted runtime-engine mutation facades fail closed before JS writes when Rust planner is missing", () => {
  const state = fakeStateWithoutPlanner();

  assert.throws(
    () => callMounted("selectRuntimeEngine", state, { engine_id: "backend.llama-cpp" }),
    (error) =>
      assertRuntimeEngineRustCoreRequired(error, "model_mount.runtime_preference.write", {
        engine_id: "backend.llama-cpp",
      }),
  );

  assert.deepEqual(state.runtimeEnginePlans, []);
  assert.deepEqual(state.recordStateCommits, []);
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

  assert.deepEqual(state.runtimeEnginePlans, []);
  assert.deepEqual(state.recordStateCommits, []);
});
