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
  schemaVersion: "schema.v1",
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

  const result = selectRuntimeEngine(state, { engineId: "backend.llama-cpp" }, deps);

  assert.equal(result.schemaVersion, "schema.v1");
  assert.equal(result.selectedEngineId, "backend.llama-cpp");
  assert.equal(state.runtimeSelections.get("default").source, "operator_runtime_select");
  assert.equal(state.writes[0][0], "runtime-preferences");
  assert.equal(state.projections, 1);
  assert.equal(state.receipts[0].kind, "runtime_engine_select");
});

test("disabled selected runtime engine resets preference to native fixture", () => {
  const state = fakeState();
  selectRuntimeEngine(state, { engineId: "backend.llama-cpp" }, deps);

  const result = updateRuntimeEngine(state, "backend.llama-cpp", {
    disabled: true,
    defaultLoadOptions: { gpu: "off" },
  }, deps);

  assert.equal(result.profile.disabled, true);
  assert.equal(state.runtimeSelections.get("default").selectedEngineId, "backend.autopilot.native-local.fixture");
  assert.equal(state.runtimeSelections.get("default").source, "operator_runtime_disable_reset");
  assert.equal(state.writes.some(([dir]) => dir === "runtime-engine-profiles"), true);
});

test("runtime engine detail includes profile, preference, instances, and latest receipts", () => {
  const state = fakeState();
  selectRuntimeEngine(state, { engineId: "backend.llama-cpp" }, deps);
  state.runtimeEngineProfiles.set("backend.llama-cpp", { id: "backend.llama-cpp", disabled: false });
  state.receipts.push({ id: "receipt_runtime", details: { runtimeEngineId: "backend.llama-cpp" } });

  const detail = runtimeEngine(state, "backend.llama-cpp", deps);

  assert.equal(detail.preference.selectedEngineId, "backend.llama-cpp");
  assert.equal(detail.profile.id, "backend.llama-cpp");
  assert.deepEqual(detail.loadedInstances.map((instance) => instance.id), ["instance_a"]);
  assert.equal(detail.latestReceipts.at(-1).id, "receipt_runtime");
});

test("removing runtime engine override clears profile and reports removal", () => {
  const state = fakeState();
  state.runtimeEngineProfiles.set("backend.llama-cpp", { id: "backend.llama-cpp", disabled: false });

  const result = removeRuntimeEngineOverride(state, "backend.llama-cpp", deps);

  assert.equal(result.removed, true);
  assert.equal(state.runtimeEngineProfiles.has("backend.llama-cpp"), false);
  assert.equal(state.writes.some(([dir]) => dir === "runtime-engine-profiles"), true);
  assert.equal(state.projections, 1);
});
