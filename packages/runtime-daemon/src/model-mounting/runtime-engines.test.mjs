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

test("selecting runtime engine persists preference and writes projection", () => {
  const state = fakeState();

  const result = selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps);

  assert.equal(result.schemaVersion, "schema.v1");
  assert.equal(result.selectedEngineId, "backend.llama-cpp");
  assert.equal(state.runtimeSelections.get("default").source, "operator_runtime_select");
  assert.equal(state.recordStateCommits[0].record_dir, "runtime-preferences");
  assert.equal(state.recordStateCommits[0].record_id, "default");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.runtime_preference.write");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt_1"]);
  assert.equal(state.recordStateCommits[0].record.selectedEngineId, "backend.llama-cpp");
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 1);
  assert.equal(state.receipts[0].kind, "runtime_engine_select");
  assert.equal(state.receipts[0].details.engine_id, "backend.llama-cpp");
  assert.equal(state.receipts[0].details.engine_kind, "llama_cpp");
  assert.deepEqual(state.receipts[0].details.default_load_options, {});
  assert.equal(Object.hasOwn(state.receipts[0].details, "engineId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "engineKind"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "defaultLoadOptions"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "checkedAt"), false);
});

test("disabled selected runtime engine resets preference to native fixture", () => {
  const state = fakeState();
  selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps);

  const result = updateRuntimeEngine(state, "backend.llama-cpp", {
    disabled: true,
    default_load_options: { gpu: "off" },
  }, deps);

  assert.equal(result.profile.disabled, true);
  assert.equal(state.runtimeSelections.get("default").selectedEngineId, "backend.autopilot.native-local.fixture");
  assert.equal(state.runtimeSelections.get("default").source, "operator_runtime_disable_reset");
  assert.equal(state.receipts[1].details.engine_id, "backend.llama-cpp");
  assert.equal(state.receipts[1].details.previous_profile_hash, "hash:{}");
  assert.deepEqual(state.receipts[1].details.default_load_options, { gpu: "off", normalized: true });
  assert.equal(Object.hasOwn(state.receipts[1].details, "engineId"), false);
  assert.equal(Object.hasOwn(state.receipts[1].details, "previousProfileHash"), false);
  assert.equal(Object.hasOwn(state.receipts[1].details, "defaultLoadOptions"), false);
  assert.equal(Object.hasOwn(state.receipts[1].details, "evidenceRefs"), false);
  assert.equal(state.recordStateCommits.some((commit) => commit.record_dir === "runtime-engine-profiles"), true);
  assert.equal(state.recordStateCommits.some((commit) => commit.record_dir === "runtime-preferences"), true);
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
      assert.equal(error.status, 409);
      assert.equal(error.code, "runtime_engine_disabled");
      assert.equal(error.details.engine_id, "backend.llama-cpp");
      assert.equal(error.details.receipt_id, "receipt.disable");
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
  selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps);
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

test("removing runtime engine override clears profile and reports removal", () => {
  const state = fakeState();
  state.runtimeEngineProfiles.set("backend.llama-cpp", { id: "backend.llama-cpp", disabled: false });

  const result = removeRuntimeEngineOverride(state, "backend.llama-cpp", deps);

  assert.equal(result.removed, true);
  assert.equal(state.runtimeEngineProfiles.has("backend.llama-cpp"), false);
  assert.equal(state.receipts[0].details.engine_id, "backend.llama-cpp");
  assert.equal(state.receipts[0].details.had_profile, true);
  assert.equal(Object.hasOwn(state.receipts[0].details, "engineId"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "hadProfile"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "previousProfileHash"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "evidenceRefs"), false);
  assert.equal(state.recordStateCommits[0].record_dir, "runtime-engine-profiles");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.runtime_engine_profile.delete");
  assert.equal(state.recordStateCommits[0].record.deleted, true);
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt_1"]);
  assert.equal(state.projections, 1);
});

test("runtime engine state persistence fails closed without Rust Agentgres record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => selectRuntimeEngine(state, { engine_id: "backend.llama-cpp" }, deps),
    (error) =>
      error.code === "runtime_engine_record_state_commit_unconfigured" &&
      error.details.record_dir === "runtime-preferences" &&
      error.details.record_id === "default" &&
      error.details.receipt_id === "receipt_1",
  );
});

test("runtime engine requests ignore retired camelCase aliases", () => {
  const state = fakeState();

  assert.throws(
    () => selectRuntimeEngine(state, { engineId: "backend.llama-cpp" }, deps),
    /missing engine_id/,
  );
  assert.equal(state.receipts.length, 0);

  const result = updateRuntimeEngine(state, "backend.llama-cpp", {
    defaultLoadOptions: { gpu: "retired" },
    loadOptions: { gpu: "also-retired" },
    operatorLabel: "Retired label",
  }, deps);

  assert.equal(result.profile.label, null);
  assert.deepEqual(result.profile.defaultLoadOptions, { normalized: true });
  assert.deepEqual(state.receipts[0].details.default_load_options, { normalized: true });
  assert.equal(Object.hasOwn(state.receipts[0].details, "defaultLoadOptions"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "operatorLabel"), false);
});

test("runtime engine operations ignore retired schemaVersion deps alias", () => {
  const state = fakeState();
  const result = selectRuntimeEngine(
    state,
    { engine_id: "backend.llama-cpp" },
    { ...deps, schemaVersion: "schema.retired" },
  );

  assert.equal(result.schemaVersion, "schema.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "runtime-preferences");
  assert.equal(state.recordStateCommits[0].record_id, "default");
  assert.equal(Object.hasOwn(state.recordStateCommits[0], "schemaVersion"), false);

  const aliasOnlyState = fakeState();
  const aliasOnly = selectRuntimeEngine(
    aliasOnlyState,
    { engine_id: "backend.llama-cpp" },
    { ...deps, schema_version: undefined, schemaVersion: "schema.retired.only" },
  );
  assert.equal(aliasOnly.schemaVersion, undefined);
});
