import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function loadModel(state, body = {}) {
  return ModelMountingState.prototype.loadModel.call(state, body);
}

function loadEstimate(state, endpoint, loadOptions = {}, runtimePreference = state.runtimePreference()) {
  return ModelMountingState.prototype.loadEstimate.call(state, endpoint, loadOptions, runtimePreference);
}

function unloadModel(state, body = {}) {
  return ModelMountingState.prototype.unloadModel.call(state, body);
}

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
    recordStateCommits: [],
    receipts: [],
    superseded: [],
    transitionRequests: [],
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
            lifecycleHash: "sha256:provider-load",
            process: { id: "process.1", pidHash: "pid.hash" },
            commandArgsHash: "args.hash",
          };
        },
        unload: async ({ instance }) => {
          this.driverCalls.push(["unload", instance.id]);
          return {
            evidenceRefs: ["driver.unload"],
            lifecycleHash: "sha256:provider-unload",
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
    planModelMountInstanceLifecycle(request) {
      this.transitionRequests.push(request);
      return {
        action: request.action,
        status: request.target_status,
        backendId: request.backend_ref,
        driver: request.driver,
        executionBackend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
        instance_lifecycle_hash: `sha256:${request.action}:${request.instance_ref}`,
        evidence_refs: [
          "rust_model_mount_instance_lifecycle",
          "rust_model_mount_provider_lifecycle_bound",
          ...request.evidence_refs,
        ],
      };
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
    },
    loadEstimate(endpointRecord, loadOptions, runtimePreference) {
      return loadEstimate(this, endpointRecord, loadOptions, runtimePreference);
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

test("loadModel rejects retired request aliases before endpoint resolution", async () => {
  const state = fakeState();
  const calls = [];
  state.resolveEndpoint = (...args) => {
    calls.push(args);
    throw new Error("resolveEndpoint should not run");
  };

  await assert.rejects(
    () =>
      loadModel(
        state,
        {
          endpointId: "endpoint.local.llama",
          modelId: "llama-test",
          loadPolicy: "resident",
          loadOptions: { estimate_only: true },
          workflowScope: "workflow-1",
          agentScope: "agent-1",
          instanceId: "instance.legacy",
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_loading_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "endpointId",
        "modelId",
        "loadPolicy",
        "loadOptions",
        "workflowScope",
        "agentScope",
        "instanceId",
      ]);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      assert.equal(Object.hasOwn(error.details, "loadPolicy"), false);
      return true;
    },
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.receipts.length, 0);
});

test("unloadModel rejects retired request aliases before instance lookup", async () => {
  const state = fakeState();
  const calls = [];
  state.instance = (...args) => {
    calls.push(["instance", ...args]);
    throw new Error("instance lookup should not run");
  };
  state.resolveEndpoint = (...args) => {
    calls.push(["resolveEndpoint", ...args]);
    throw new Error("endpoint lookup should not run");
  };

  await assert.rejects(
    () =>
      unloadModel(
        state,
        {
          endpointId: "endpoint.local.llama",
          modelId: "llama-test",
          loadPolicy: "resident",
          loadOptions: { estimate_only: true },
          workflowScope: "workflow-1",
          agentScope: "agent-1",
          instanceId: "instance.legacy",
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_loading_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "endpointId",
        "modelId",
        "loadPolicy",
        "loadOptions",
        "workflowScope",
        "agentScope",
        "instanceId",
      ]);
      return true;
    },
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.receipts.length, 0);
});

test("loadModel returns estimate-only envelope without invoking provider driver", async () => {
  const state = fakeState();

  const result = await loadModel(
    state,
    { endpoint_id: "endpoint.local.llama", load_policy: "resident", load_options: { estimate_only: true, context_length: 2048 } },
    deps,
  );

  assert.equal(result.schemaVersion, "ioi.model-mounting.runtime.v1");
  assert.equal(result.status, "estimate_only");
  assert.equal(result.backend_id, "backend.autopilot.native-local.fixture");
  assert.equal(result.provider_kind, "ioi_native_local");
  assert.equal(result.runtime_engine_profile.id, "engine.native");
  assert.equal(result.estimate.contextLength, 2048);
  assert.equal(result.receipt_id, null);
  assert.deepEqual(result.evidence_refs, [
    "model_mount_model_loading_js_facade_retired",
    "model_load_estimate_projection_only",
  ]);
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(Object.hasOwn(result, "backendId"), false);
  assert.equal(Object.hasOwn(result, "runtimeEngineProfile"), false);
  assert.equal(Object.hasOwn(result, "receiptId"), false);
});

test("loadModel mutation facade fails closed before JS driver, receipt, or instance write", async () => {
  const state = fakeState();

  await assert.rejects(
    () =>
      loadModel(
        state,
        { endpoint_id: "endpoint.local.llama", id: "instance.explicit", load_options: { identifier: "llama-test" } },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_model_loading_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.instance_lifecycle");
      assert.equal(error.details.operation, "model_load");
      assert.equal(error.details.operation_kind, "model_mount.instance.load");
      assert.equal(error.details.endpoint_id, "endpoint.local.llama");
      assert.equal(error.details.model_id, "llama-test");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(error.details.provider_kind, "ioi_native_local");
      assert.equal(error.details.backend_id, "backend.autopilot.native-local.fixture");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.instances.has("instance.explicit"), false);
  assert.deepEqual(state.superseded, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.transitionRequests, []);
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

  assert.equal(estimate.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(estimate.contextLength, 2048);
  assert.equal(estimate.parallelism, 4);
  assert.equal(estimate.gpuOffload, "full");
  assert.equal(estimate.realInference, false);
  assert.deepEqual(estimate.evidenceRefs, ["model_load_option_estimate", "runtime_engine_preference"]);
});

test("loadModel fails closed for non-migrated provider before JS driver execution", async () => {
  const state = fakeState();
  state.endpointRecord = {
    ...state.endpointRecord,
    providerId: "provider.remote",
    apiFormat: "openai_compatible",
    backendId: "backend.remote",
  };
  state.endpointById.set(state.endpointRecord.id, state.endpointRecord);
  state.providerRecord = {
    id: "provider.remote",
    kind: "openai_compatible",
    driver: "openai_compatible",
    apiFormat: "openai_compatible",
  };

  await assert.rejects(
    () => loadModel(state, { endpoint_id: "endpoint.local.llama", id: "instance.remote" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_model_loading_rust_core_required");
      assert.equal(error.details.operation, "model_load");
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "openai_compatible");
      assert.equal(error.details.provider_driver, "openai_compatible");
      assert.equal(error.details.api_format, "openai_compatible");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.instances.has("instance.remote"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("unloadModel fails closed for non-migrated provider before JS driver execution", async () => {
  const state = fakeState();
  state.providerRecord = {
    id: "provider.remote",
    kind: "custom_http",
    driver: "openai_compatible",
    apiFormat: "openai_compatible",
  };
  state.instances.set("instance.remote", {
    id: "instance.remote",
    endpointId: "endpoint.local.llama",
    providerId: "provider.remote",
    modelId: "llama-test",
    status: "loaded",
  });

  await assert.rejects(
    () => unloadModel(state, { instance_id: "instance.remote" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_model_loading_rust_core_required");
      assert.equal(error.details.operation, "model_unload");
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "custom_http");
      assert.equal(error.details.provider_driver, "openai_compatible");
      assert.equal(error.details.api_format, "openai_compatible");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.instances.get("instance.remote").status, "loaded");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("unloadModel mutation facade fails closed before JS driver, receipt, or instance write", async () => {
  const state = fakeState();
  const loaded = {
    id: "instance.loaded",
    endpointId: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    status: "loaded",
    providerEvidenceRefs: ["previous"],
  };
  state.instances.set("instance.loaded", loaded);

  await assert.rejects(
    () => unloadModel(state, { instance_id: "instance.loaded" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_model_loading_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.instance_lifecycle");
      assert.equal(error.details.operation, "model_unload");
      assert.equal(error.details.operation_kind, "model_mount.instance.unload");
      assert.equal(error.details.instance_id, "instance.loaded");
      assert.equal(error.details.endpoint_id, "endpoint.local.llama");
      assert.equal(error.details.model_id, "llama-test");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(error.details.provider_kind, "ioi_native_local");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "instanceId"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.instances.get("instance.loaded"), loaded);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.transitionRequests, []);
});

test("loadModel fails closed before Rust planning or Agentgres commit shims are used", async () => {
  const state = fakeState();
  state.planModelMountInstanceLifecycle = () => ({ status: "loaded" });
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () => loadModel(state, { endpoint_id: "endpoint.local.llama", id: "instance.fail" }, deps),
    (error) => error.code === "model_mount_model_loading_rust_core_required",
  );

  assert.equal(state.instances.has("instance.fail"), false);
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.writes.length, 0);
});

test("unloadModel fails closed before Rust planning or Agentgres commit shims are used", async () => {
  const state = fakeState();
  const loaded = {
    id: "instance.loaded",
    endpointId: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    status: "loaded",
    providerEvidenceRefs: ["previous"],
  };
  state.instances.set("instance.loaded", {
    ...loaded,
  });
  state.planModelMountInstanceLifecycle = () => ({ status: "unloaded" });
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () => unloadModel(state, { instance_id: "instance.loaded" }, deps),
    (error) => error.code === "model_mount_model_loading_rust_core_required",
  );

  assert.deepEqual(state.instances.get("instance.loaded"), loaded);
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.writes.length, 0);
});
