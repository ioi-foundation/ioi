import assert from "node:assert/strict";
import test from "node:test";

import {
  loadEstimate,
  loadModel,
  unloadModel,
} from "./model-loading-operations.mjs";

function fakeState() {
  const endpoint = {
    id: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    apiFormat: "openai",
    backendId: null,
    loadPolicy: { mode: "on_demand" },
    contextWindow: 4096,
  };
  const provider = {
    id: "provider.local",
    kind: "ioi_native_local",
    driver: "native_local",
    apiFormat: "openai",
  };
  return {
    artifacts: new Map([
      ["artifact.llama", {
        id: "artifact.llama",
        modelId: "llama-test",
        contextWindow: 8192,
        sizeBytes: 4096,
      }],
    ]),
    endpointRecord: endpoint,
    instances: new Map(),
    providerRecord: provider,
    receipts: [],
    superseded: [],
    writes: [],
    now: "2026-06-04T00:00:00.000Z",
    driverCalls: [],
    driverForProvider() {
      return {
        load: async ({ endpoint: loadedEndpoint, body }) => {
          this.driverCalls.push(["load", loadedEndpoint.id, body.loadOptions]);
          return {
            backend: "native_local",
            backendId: "backend.native",
            estimate: { fromDriver: true },
            evidenceRefs: ["driver.load"],
            process: { id: "process.1", pidHash: "pid.hash" },
            commandArgsHash: "args.hash",
          };
        },
        unload: async ({ instance }) => {
          this.driverCalls.push(["unload", instance.id]);
          return {
            evidenceRefs: ["driver.unload"],
            process: { id: "process.1" },
          };
        },
      };
    },
    endpointById: new Map([["endpoint.local.llama", endpoint]]),
    endpoint(endpointId) {
      const record = this.endpointById.get(endpointId);
      if (!record) throw new Error(`missing endpoint ${endpointId}`);
      return record;
    },
    getModel(modelId) {
      return [...this.artifacts.values()].find((artifact) => artifact.modelId === modelId);
    },
    instance(instanceId) {
      const record = this.instances.get(instanceId);
      if (!record) throw new Error(`missing instance ${instanceId}`);
      return record;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    loadEstimate(endpointRecord, loadOptions, runtimePreference) {
      return loadEstimate(this, endpointRecord, loadOptions, runtimePreference, deps);
    },
    loadedInstanceForEndpoint(endpointId) {
      return [...this.instances.values()].find((instance) => instance.endpointId === endpointId && instance.status === "loaded");
    },
    nowIso() {
      return this.now;
    },
    provider(providerId) {
      if (providerId !== this.providerRecord.id) throw new Error(`missing provider ${providerId}`);
      return this.providerRecord;
    },
    resolveEndpoint(endpointId, modelId) {
      if (endpointId) return this.endpoint(endpointId);
      if (modelId === this.endpointRecord.modelId) return this.endpointRecord;
      throw new Error("missing endpoint");
    },
    runtimeDefaultLoadOptions() {
      return { ttlSeconds: 120, parallel: 2 };
    },
    runtimeEngineProfile(engineId) {
      return { id: engineId, label: "Native" };
    },
    runtimePreference() {
      return { selectedEngineId: "engine.native" };
    },
    runtimePreferenceForEndpoint() {
      return { selectedEngineId: "engine.native" };
    },
    supersedeLoadedInstances(endpointId, keepInstanceId) {
      this.superseded.push([endpointId, keepInstanceId]);
      return true;
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
  };
}

const deps = {
  defaultBackendForProvider(provider) {
    return provider.kind === "ioi_native_local" ? "backend.native" : "backend.remote";
  },
  driverNameForProvider(provider) {
    return provider.driver ?? "fixture";
  },
  estimateNativeLocalResources(artifact) {
    return {
      contextWindow: artifact.contextWindow ?? 2048,
      estimatedVramBytes: 1024,
      sizeBytes: artifact.sizeBytes ?? 0,
      realInference: true,
    };
  },
  expiresAt(now, loadPolicy) {
    return loadPolicy.idleTtlSeconds ? "2026-06-04T00:02:00.000Z" : null;
  },
  hasExplicitTtlOption(value = {}) {
    return Object.hasOwn(value, "ttlSeconds") || Object.hasOwn(value, "ttl_seconds");
  },
  normalizeLoadOptions(value, loadPolicy) {
    return {
      estimateOnly: Boolean(value.estimate_only ?? value.estimateOnly),
      ttlSeconds: value.ttlSeconds ?? value.ttl_seconds ?? loadPolicy.idleTtlSeconds ?? null,
      parallel: value.parallel ?? null,
      gpu: value.gpu ?? null,
      contextLength: value.context_length ?? value.contextLength ?? null,
      identifier: value.identifier ?? null,
    };
  },
  normalizeLoadPolicy(value) {
    return { mode: value?.mode ?? value ?? "on_demand" };
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  schemaVersion: "schema.model-loading.test",
};

test("loadModel returns estimate-only envelope without invoking provider driver", async () => {
  const state = fakeState();

  const result = await loadModel(
    state,
    { endpoint_id: "endpoint.local.llama", load_policy: "resident", load_options: { estimate_only: true, context_length: 2048 } },
    deps,
  );

  assert.equal(result.schemaVersion, "schema.model-loading.test");
  assert.equal(result.status, "estimate_only");
  assert.equal(result.backendId, "backend.native");
  assert.equal(result.runtimeEngineProfile.id, "engine.native");
  assert.equal(result.estimate.contextLength, 2048);
  assert.equal(result.receiptId, "receipt.model_load_estimate.1");
  assert.deepEqual(state.driverCalls, []);
});

test("loadModel persists loaded instance, supersedes previous instances, and records receipt", async () => {
  const state = fakeState();

  const instance = await loadModel(
    state,
    { endpoint_id: "endpoint.local.llama", id: "instance.explicit", load_options: { identifier: "llama-test" } },
    deps,
  );

  assert.equal(instance.id, "instance.explicit");
  assert.equal(instance.status, "loaded");
  assert.equal(instance.backendId, "backend.native");
  assert.equal(instance.driver, "native_local");
  assert.equal(instance.runtimeEngineId, "engine.native");
  assert.equal(instance.backendProcessId, "process.1");
  assert.deepEqual(instance.providerEvidenceRefs, ["driver.load"]);
  assert.equal(state.instances.get(instance.id), instance);
  assert.deepEqual(state.superseded, [["endpoint.local.llama", "instance.explicit"]]);
  assert.equal(state.writes.at(-1)[0], "model-instances");
  assert.equal(state.receipts.at(-1).kind, "model_load");
  assert.equal(state.receipts.at(-1).details.commandArgsHash, "args.hash");
});

test("loadEstimate derives native resource estimate and backend defaults", () => {
  const state = fakeState();

  const estimate = loadEstimate(
    state,
    state.endpointRecord,
    { contextLength: 2048, parallel: 4, gpu: "full", identifier: "llama" },
    { selectedEngineId: "engine.native" },
    deps,
  );

  assert.equal(estimate.backendId, "backend.native");
  assert.equal(estimate.contextLength, 2048);
  assert.equal(estimate.parallelism, 4);
  assert.equal(estimate.gpuOffload, "full");
  assert.equal(estimate.realInference, true);
  assert.deepEqual(estimate.evidenceRefs, ["model_load_option_estimate", "runtime_engine_preference"]);
});

test("unloadModel updates loaded instance and records provider evidence", async () => {
  const state = fakeState();
  state.instances.set("instance.loaded", {
    id: "instance.loaded",
    endpointId: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    status: "loaded",
    providerEvidenceRefs: ["previous"],
  });

  const result = await unloadModel(state, { instance_id: "instance.loaded" }, deps);

  assert.equal(result.status, "unloaded");
  assert.equal(result.unloadedAt, state.now);
  assert.deepEqual(result.providerEvidenceRefs, ["driver.unload"]);
  assert.equal(state.instances.get("instance.loaded"), result);
  assert.equal(state.writes.at(-1)[0], "model-instances");
  assert.equal(state.receipts.at(-1).kind, "model_unload");
  assert.equal(state.receipts.at(-1).details.backendProcess.id, "process.1");
});
