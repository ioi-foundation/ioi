import assert from "node:assert/strict";
import test from "node:test";

import {
  listRuntimeEngines,
  removeRuntimeEngineOverride,
  runtimeEngine,
  runtimePreference,
  runtimePreferenceForEndpoint,
  selectRuntimeEngine,
  updateRuntimeEngine,
} from "./runtime-engines.mjs";

function fakeState() {
  const state = {
    stateDir: "/tmp/ioi-runtime-engines-test",
    runtimeSelections: new Map(),
    runtimeEngineProfiles: new Map(),
    recordStateCommits: [],
    receipts: [],
    writes: [],
    projections: 0,
    backendRegistry() {
      return [
        {
          id: "backend.autopilot.native-local.fixture",
          kind: "native_local",
          label: "Native fixture",
          status: "available",
          supportedFormats: ["gguf", "fixture"],
        },
        {
          id: "backend.llama-cpp",
          kind: "llama_cpp",
          label: "llama.cpp",
          status: "configured",
          supportedFormats: ["gguf"],
          processStatus: "stopped",
        },
      ];
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt_${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    listInstances() {
      return [{ id: "instance_a", backendId: "backend.llama-cpp", runtimeEngineId: "backend.llama-cpp" }];
    },
    listReceipts() {
      return this.receipts;
    },
    lmStudioRuntimeEngines() {
      return [
        {
          id: "runtime.lmstudio.cpu",
          kind: "lm_studio",
          label: "LM Studio CPU",
          status: "available",
          selected: false,
          modelFormat: "gguf",
          source: "lm_studio_public_lms",
        },
      ];
    },
    nowIso() {
      return "2026-06-03T12:00:00.000Z";
    },
    writeMap(dir, map) {
      this.writes.push([dir, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        source: "rust_agentgres_runtime_model_mount_record_state_commit_command",
        backend: "rust_agentgres_storage",
        record: {
          schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
          record_dir: request.record_dir,
          record_id: request.record_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: `${request.record_dir}/${request.record_id}.json`,
            object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
            content_hash: "sha256:runtime-engine-content",
            payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
            receipt_refs: request.receipt_refs,
            admission: { admission_hash: "sha256:runtime-engine-admission" },
          },
          commit_hash: "sha256:runtime-engine-commit",
        },
        storage_record: {
          record_path: `${request.record_dir}/${request.record_id}.json`,
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
          content_hash: "sha256:runtime-engine-content",
          payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
          receipt_refs: request.receipt_refs,
          admission: { admission_hash: "sha256:runtime-engine-admission" },
        },
        record_dir: request.record_dir,
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
        content_hash: "sha256:runtime-engine-content",
        admission_hash: "sha256:runtime-engine-admission",
        commit_hash: "sha256:runtime-engine-commit",
        written_record: { record_path: `${request.record_dir}/${request.record_id}.json` },
        evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
  return state;
}

const deps = {
  normalizeRuntimeEngineDefaultLoadOptions: (value) => ({ ...value, normalized: true }),
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
  requiredString(value, field) {
    if (typeof value !== "string" || !value) throw new Error(`missing ${field}`);
    return value;
  },
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  safeFileName: (value) => String(value).replace(/[^a-z0-9._-]+/gi, "_"),
  schema_version: "schema.v1",
  stableHash: (value) => `hash:${JSON.stringify(value)}`,
};

test("runtime preference defaults to native fixture and endpoint backend can override", () => {
  const state = fakeState();

  assert.deepEqual(runtimePreference(state), {
    id: "default",
    selectedEngineId: "backend.autopilot.native-local.fixture",
    selectedAt: null,
    receiptId: "none",
    source: "default_native_local_runtime",
    defaultLoadOptions: {},
  });
  assert.equal(runtimePreferenceForEndpoint(state, { backendId: "backend.llama-cpp" }).selectedEngineId, "backend.llama-cpp");
  assert.equal(runtimePreferenceForEndpoint(state, { backendId: "backend.missing" }).selectedEngineId, "backend.autopilot.native-local.fixture");
});

test("runtime engine listing applies profiles, active selection, and priority ordering", () => {
  const state = fakeState();
  state.runtimeEngineProfiles.set("backend.llama-cpp", {
    id: "backend.llama-cpp",
    label: "Operator llama",
    priority: 1,
    defaultLoadOptions: { gpu: "auto" },
    receiptId: "receipt_profile",
  });

  const engines = listRuntimeEngines(state);

  assert.equal(engines[0].id, "backend.llama-cpp");
  assert.equal(engines[0].label, "Operator llama");
  assert.equal(engines[0].selected, true);
  assert.deepEqual(engines[0].operatorProfile.defaultLoadOptions, { gpu: "auto" });
  assert.equal(engines.find((engine) => engine.id === "backend.autopilot.native-local.fixture").operatorProfile.configured, false);
});

test("runtime engine mutation facade fails closed until Rust core owns it", () => {
  const state = fakeState();

  const cases = [
    [
      () => selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps),
      "model_mount.runtime_preference.write",
    ],
    [
      () => updateRuntimeEngine(state, "backend.llama-cpp", { disabled: true, default_load_options: { gpu: "off" } }, deps),
      "model_mount.runtime_engine_profile.write",
    ],
    [
      () => removeRuntimeEngineOverride(state, "backend.llama-cpp", deps),
      "model_mount.runtime_engine_profile.delete",
    ],
  ];

  for (const [run, operationKind] of cases) {
    assert.throws(run, (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_runtime_engine_rust_core_required");
      assert.equal(error.details.engine_id, "backend.llama-cpp");
      assert.equal(error.details.operation_kind, operationKind);
      assert.equal(error.details.rust_core_boundary, "model_mount.runtime_engine");
      assert.deepEqual(error.details.evidence_refs, [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "engineId"), false);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    });
  }

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
  assert.equal(state.runtimeSelections.has("default"), false);
  assert.equal(state.runtimeEngineProfiles.has("backend.llama-cpp"), false);
});

test("runtime engine errors use canonical details without retired aliases", () => {
  const state = fakeState();
  state.runtimeEngineProfiles.set("backend.llama-cpp", {
    id: "backend.llama-cpp",
    disabled: true,
    receiptId: "receipt.disable",
  });

  assert.throws(
    () => selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_runtime_engine_rust_core_required");
      assert.equal(error.details.engine_id, "backend.llama-cpp");
      assert.equal(Object.hasOwn(error.details, "engineId"), false);
      assert.equal(Object.hasOwn(error.details, "receiptId"), false);
      return true;
    },
  );

  assert.throws(
    () => runtimeEngine(state, "backend.missing", deps),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.engine_id, "backend.missing");
      assert.equal(Object.hasOwn(error.details, "engineId"), false);
      return true;
    },
  );
});

test("runtime engine detail includes profile, preference, instances, and latest receipts", () => {
  const state = fakeState();
  state.runtimeSelections.set("default", {
    id: "default",
    selectedEngineId: "backend.llama-cpp",
    selectedAt: "2026-06-03T12:00:00.000Z",
    receiptId: "receipt_select",
    source: "rust_daemon_core_runtime_engine_projection",
    defaultLoadOptions: {},
  });
  state.runtimeEngineProfiles.set("backend.llama-cpp", { id: "backend.llama-cpp", disabled: false });
  state.receipts.push({ id: "receipt_legacy", details: { runtimeEngineId: "backend.llama-cpp" } });
  state.receipts.push({ id: "receipt_runtime", details: { runtime_engine_id: "backend.llama-cpp" } });

  const detail = runtimeEngine(state, "backend.llama-cpp", deps);

  assert.equal(detail.preference.selectedEngineId, "backend.llama-cpp");
  assert.equal(detail.profile.id, "backend.llama-cpp");
  assert.deepEqual(detail.loadedInstances.map((instance) => instance.id), ["instance_a"]);
  assert.equal(detail.latestReceipts.at(-1).id, "receipt_runtime");
  assert.equal(detail.latestReceipts.some((receipt) => receipt.id === "receipt_legacy"), false);
});

test("runtime engine mutation facade does not delete projected profiles", () => {
  const state = fakeState();
  state.runtimeEngineProfiles.set("backend.llama-cpp", { id: "backend.llama-cpp", disabled: false });

  assert.throws(
    () => removeRuntimeEngineOverride(state, "backend.llama-cpp", deps),
    (error) => error.code === "model_mount_runtime_engine_rust_core_required",
  );

  assert.equal(state.runtimeEngineProfiles.has("backend.llama-cpp"), true);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("runtime engine requests ignore retired camelCase aliases", () => {
  const state = fakeState();

  assert.throws(
    () => selectRuntimeEngine(state, { engineId: "backend.llama-cpp" }, deps),
    /missing engine_id/,
  );
  assert.equal(state.receipts.length, 0);

  assert.throws(
    () => updateRuntimeEngine(state, "backend.llama-cpp", {
      defaultLoadOptions: { gpu: "retired" },
      loadOptions: { gpu: "also-retired" },
      operatorLabel: "Retired label",
    }, deps),
    (error) => {
      assert.equal(error.code, "model_mount_runtime_engine_rust_core_required");
      assert.equal(Object.hasOwn(error.details, "defaultLoadOptions"), false);
      assert.equal(Object.hasOwn(error.details, "operatorLabel"), false);
      return true;
    },
  );
  assert.equal(state.receipts.length, 0);
});

test("runtime engine operations ignore retired schemaVersion deps alias", () => {
  const state = fakeState();
  assert.throws(
    () => selectRuntimeEngine(
      state,
      { engine_id: "backend.llama-cpp" },
      { ...deps, schemaVersion: "schema.retired" },
    ),
    (error) => error.code === "model_mount_runtime_engine_rust_core_required",
  );
  assert.deepEqual(state.recordStateCommits, []);

  const aliasOnlyState = fakeState();
  assert.throws(
    () => selectRuntimeEngine(
      aliasOnlyState,
      { engine_id: "backend.llama-cpp" },
      { ...deps, schema_version: undefined, schemaVersion: "schema.retired.only" },
    ),
    (error) => error.code === "model_mount_runtime_engine_rust_core_required",
  );
  assert.deepEqual(aliasOnlyState.recordStateCommits, []);
});
