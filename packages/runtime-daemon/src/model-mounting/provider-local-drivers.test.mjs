import assert from "node:assert/strict";
import test from "node:test";

import {
  FixtureModelProviderDriver,
  NativeLocalModelProviderDriver,
} from "./provider-local-drivers.mjs";

function fakeNativeState() {
  const logs = [];
  const lifecycleRequests = [];
  const inventoryRequests = [];
  const artifacts = [
    {
      id: "artifact.native",
      providerId: "provider.native",
      modelId: "native:model",
    },
    {
      id: "artifact.fixture",
      providerId: "provider.fixture",
      modelId: "fixture:model",
    },
  ];
  const instances = [
    {
      id: "instance.native.loaded",
      providerId: "provider.native",
      status: "loaded",
      modelId: "native:model",
    },
    {
      id: "instance.fixture.loaded",
      providerId: "provider.fixture",
      status: "loaded",
      modelId: "fixture:model",
    },
    {
      id: "instance.native.stopped",
      providerId: "provider.native",
      status: "stopped",
      modelId: "native:model",
    },
  ];
  const processRecord = {
    id: "backend_process_native",
    backendId: "backend.autopilot.native-local.fixture",
    pidHash: "pid-hash",
    argsHash: "args-hash",
    evidenceRefs: ["fake_process"],
  };
  return {
    logs,
    lifecycleRequests,
    inventoryRequests,
    getModel(modelId) {
      return {
        id: "artifact.native",
        modelId,
        sizeBytes: 42,
        capabilities: ["chat", "responses", "embeddings"],
      };
    },
    listArtifacts() {
      return artifacts;
    },
    listInstances() {
      return instances;
    },
    ensureBackendProcess(backendId) {
      assert.equal(backendId, "backend.autopilot.native-local.fixture");
      return processRecord;
    },
    backendProcessForBackend(backendId) {
      assert.equal(backendId, "backend.autopilot.native-local.fixture");
      return processRecord;
    },
    backendProcessSnapshot(record) {
      return record ? { id: record.id, evidenceRefs: record.evidenceRefs } : null;
    },
    loadedInstanceForEndpoint() {
      return { loadOptions: { idleTtlSeconds: 900 } };
    },
    writeBackendLog(endpointId, event) {
      logs.push({ endpointId, ...event });
    },
    planModelMountProviderLifecycle(request) {
      lifecycleRequests.push(request);
      const isFixture = request.execution_backend === "rust_model_mount_fixture_lifecycle";
      const status =
        request.action === "health"
          ? request.provider_status === "blocked"
            ? "blocked"
            : "available"
          : request.action === "load"
            ? "loaded"
            : "unloaded";
      return {
        status,
        backendId: request.backend_ref,
        providerBackend: isFixture ? "ioi_fixture" : "autopilot.native_local.fixture",
        driver: isFixture ? "fixture" : "native_local",
        executionBackend: request.execution_backend,
        lifecycle_hash: `sha256:${request.action}`,
        evidence_refs: [
          "rust_model_mount_provider_lifecycle",
          isFixture
            ? "rust_model_mount_fixture_lifecycle_backend"
            : "rust_model_mount_native_local_lifecycle_backend",
          ...request.process_evidence_refs,
          ...request.evidence_refs,
        ],
      };
    },
    planModelMountProviderInventory(request) {
      inventoryRequests.push(request);
      const isFixture = request.execution_backend === "rust_model_mount_fixture_inventory";
      return {
        status: "listed",
        backendId: request.backend_ref,
        providerBackend: isFixture ? "ioi_fixture" : "autopilot.native_local.fixture",
        driver: isFixture ? "fixture" : "native_local",
        executionBackend: request.execution_backend,
        itemRefs: request.item_refs,
        itemCount: request.item_refs.length,
        inventory_hash: `sha256:${request.action}:${request.item_refs.length}`,
        evidence_refs: [
          "rust_model_mount_provider_inventory",
          isFixture
            ? "rust_model_mount_fixture_inventory_backend"
            : "rust_model_mount_native_local_inventory_backend",
          ...request.evidence_refs,
        ],
      };
    },
  };
}

test("local provider drivers fail closed for retired direct non-stream invoke", async () => {
  const fixture = new FixtureModelProviderDriver();
  await assert.rejects(
    () =>
      fixture.invoke({
        kind: "chat.completions",
        input: { messages: [{ role: "user", content: "hello" }] },
        endpoint: {
          modelId: "local:auto",
          apiFormat: "ioi_fixture",
        },
      }),
    (error) => error.code === "model_mount_local_provider_direct_invoke_retired",
  );

  const state = fakeNativeState();
  const native = new NativeLocalModelProviderDriver();
  await assert.rejects(
    () =>
      native.invoke({
        kind: "responses",
        input: { input: [{ role: "user", content: "hello" }] },
        endpoint: {
          id: "endpoint.native",
          modelId: "autopilot:native-fixture",
        },
        state,
      }),
    (error) => error.code === "model_mount_local_provider_direct_invoke_retired",
  );
  assert.equal(state.logs.length, 0);
});

test("native-local provider driver plans health through Rust model_mount", async () => {
  const state = fakeNativeState();
  const driver = new NativeLocalModelProviderDriver();

  const health = await driver.health(
    { id: "provider.native", kind: "ioi_native_local", status: "configured" },
    { state },
  );

  assert.equal(health.status, "available");
  assert.equal(health.lifecycleHash, "sha256:health");
  assert.equal(health.model_mount_provider_lifecycle.action, "health");
  assert.equal(health.model_mount_provider_lifecycle.lifecycle_hash, "sha256:health");
  assert.ok(health.evidenceRefs.includes("rust_model_mount_provider_lifecycle"));
  assert.equal(state.lifecycleRequests.at(-1).action, "health");
  assert.equal(state.lifecycleRequests.at(-1).provider_status, "configured");

  const blocked = await driver.health(
    { id: "provider.native", kind: "ioi_native_local", status: "blocked" },
    { state },
  );

  assert.equal(blocked.status, "blocked");
  assert.equal(state.lifecycleRequests.at(-1).provider_status, "blocked");
});

test("fixture provider driver plans health and lifecycle through Rust model_mount", async () => {
  const state = fakeNativeState();
  const driver = new FixtureModelProviderDriver();
  const provider = { id: "provider.fixture", kind: "local_folder", status: "configured" };
  const endpoint = {
    id: "endpoint.fixture",
    providerId: "provider.fixture",
    modelId: "fixture:model",
    apiFormat: "ioi_fixture",
    backendId: "backend.fixture",
  };

  const health = await driver.health(provider, { state });
  assert.equal(health.status, "available");
  assert.equal(health.lifecycleHash, "sha256:health");
  assert.equal(health.model_mount_provider_lifecycle.action, "health");
  assert.equal(health.model_mount_provider_lifecycle.lifecycle_hash, "sha256:health");
  assert.equal(state.lifecycleRequests.at(-1).execution_backend, "rust_model_mount_fixture_lifecycle");
  assert.ok(health.evidenceRefs.includes("rust_model_mount_fixture_lifecycle_backend"));

  const load = await driver.load({ state, provider, endpoint });
  assert.equal(load.status, "loaded");
  assert.equal(load.backend, "ioi_fixture");
  assert.equal(load.driver, "fixture");
  assert.equal(load.lifecycleHash, "sha256:load");

  const unload = await driver.unload({ state, provider, endpoint });
  assert.equal(unload.status, "unloaded");
  assert.equal(unload.backendId, "backend.fixture");
  assert.equal(unload.lifecycleHash, "sha256:unload");
});

test("local provider drivers plan model and loaded inventory through Rust model_mount", async () => {
  const state = fakeNativeState();
  const native = new NativeLocalModelProviderDriver();
  const fixture = new FixtureModelProviderDriver();

  const nativeModels = await native.listModels({
    state,
    provider: { id: "provider.native", kind: "ioi_native_local", status: "configured" },
  });
  assert.equal(nativeModels.length, 1);
  assert.equal(nativeModels[0].inventoryHash, "sha256:list_models:1");
  assert.ok(nativeModels[0].inventoryEvidenceRefs.includes("rust_model_mount_provider_inventory"));
  assert.equal(nativeModels.modelMountProviderInventory.inventoryHash, "sha256:list_models:1");
  assert.equal(nativeModels.modelMountProviderInventory.action, "list_models");
  assert.equal(state.inventoryRequests.at(-1).action, "list_models");
  assert.equal(state.inventoryRequests.at(-1).execution_backend, "rust_model_mount_native_local_inventory");
  assert.deepEqual(state.inventoryRequests.at(-1).item_refs, ["artifact.native"]);

  const nativeLoaded = await native.listLoaded({
    state,
    provider: { id: "provider.native", kind: "ioi_native_local", status: "configured" },
  });
  assert.equal(nativeLoaded.length, 1);
  assert.equal(nativeLoaded[0].inventoryHash, "sha256:list_loaded:1");
  assert.equal(nativeLoaded.modelMountProviderInventory.action, "list_loaded");
  assert.ok(nativeLoaded[0].backendEvidenceRefs.includes("rust_model_mount_native_local_inventory_backend"));
  assert.equal(state.inventoryRequests.at(-1).action, "list_loaded");
  assert.deepEqual(state.inventoryRequests.at(-1).item_refs, ["instance.native.loaded"]);

  const fixtureModels = await fixture.listModels({
    state,
    provider: { id: "provider.fixture", kind: "local_folder", status: "configured" },
  });
  assert.equal(fixtureModels.length, 1);
  assert.equal(fixtureModels[0].inventoryHash, "sha256:list_models:1");
  assert.equal(state.inventoryRequests.at(-1).execution_backend, "rust_model_mount_fixture_inventory");
  assert.deepEqual(state.inventoryRequests.at(-1).item_refs, ["artifact.fixture"]);

  const fixtureLoaded = await fixture.listLoaded({
    state,
    provider: { id: "provider.fixture", kind: "local_folder", status: "configured" },
  });
  assert.equal(fixtureLoaded.length, 1);
  assert.ok(fixtureLoaded[0].backendEvidenceRefs.includes("rust_model_mount_fixture_inventory_backend"));
  assert.equal(state.inventoryRequests.at(-1).action, "list_loaded");
});

test("local provider inventory listing fails closed without Rust planner result", async () => {
  const driver = new NativeLocalModelProviderDriver();
  const state = {
    ...fakeNativeState(),
    planModelMountProviderInventory() {
      return { status: "listed", driver: "native_local" };
    },
  };

  await assert.rejects(
    () =>
      driver.listModels({
        state,
        provider: { id: "provider.native", kind: "ioi_native_local" },
      }),
    (error) => error.code === "model_mount_provider_inventory_planning_required",
  );

  const fixture = new FixtureModelProviderDriver();
  await assert.rejects(
    () =>
      fixture.listLoaded({
        state: {
          ...fakeNativeState(),
          planModelMountProviderInventory() {
            return null;
          },
        },
        provider: { id: "provider.fixture", kind: "local_folder" },
      }),
    (error) => error.code === "model_mount_fixture_provider_inventory_planning_required",
  );
});

test("native-local provider driver keeps load control and retires direct stream production", async () => {
  const state = fakeNativeState();
  const driver = new NativeLocalModelProviderDriver();
  const endpoint = {
    id: "endpoint.native",
    modelId: "autopilot:native-fixture",
    loadPolicy: { mode: "on_demand" },
  };

  const load = await driver.load({ state, endpoint, body: { idle_ttl_seconds: 120 } });
  assert.equal(load.status, "loaded");
  assert.equal(load.backend, "autopilot.native_local.fixture");
  assert.equal(load.lifecycleHash, "sha256:load");
  assert.ok(load.evidenceRefs.includes("rust_model_mount_provider_lifecycle"));
  assert.equal(state.lifecycleRequests.at(-1).execution_backend, "rust_model_mount_native_local_lifecycle");
  assert.deepEqual(state.lifecycleRequests.at(-1).process_evidence_refs, ["fake_process"]);
  assert.equal(state.logs.at(-1).event, "load");

  await assert.rejects(
    () =>
      driver.streamInvoke({
        kind: "chat.completions",
        input: { messages: [{ role: "user", content: "summarize repo state" }] },
        endpoint,
        state,
      }),
    (error) => error.code === "model_mount_local_provider_direct_stream_retired",
  );
  assert.equal(state.logs.at(-1).event, "load");

  const unload = await driver.unload({ state, endpoint });
  assert.equal(unload.status, "unloaded");
  assert.equal(unload.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(unload.lifecycleHash, "sha256:unload");
  assert.ok(unload.evidenceRefs.includes("rust_model_mount_native_local_lifecycle_backend"));
  assert.equal(state.lifecycleRequests.at(-1).action, "unload");
  assert.equal(state.logs.at(-1).event, "unload");
});
