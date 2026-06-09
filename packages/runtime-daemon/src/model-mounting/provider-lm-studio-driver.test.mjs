import assert from "node:assert/strict";
import test from "node:test";

import { LmStudioModelProviderDriver } from "./provider-lm-studio-driver.mjs";

function provider(lmsPath = null) {
  return {
    id: "provider.lmstudio",
    kind: "lm_studio",
    discovery: lmsPath ? { publicCli: { path: lmsPath } } : {},
  };
}

function fakeState(homeDir = "/tmp/no-lmstudio") {
  return {
    homeDir,
    nowIso() {
      return "2026-06-03T00:00:00.000Z";
    },
  };
}

function assertLmStudioCliRetired(error, operation, operationKind = null) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_lm_studio_public_cli_retired");
  assert.equal(error.details.rust_core_boundary, "model_mount.provider_lm_studio");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.provider_id, "provider.lmstudio");
  assert.equal(error.details.provider_kind, "lm_studio");
  if (operationKind) assert.equal(error.details.operation_kind, operationKind);
  assert.deepEqual(error.details.evidence_refs, [
    "lm_studio_public_cli_driver_retired",
    "rust_daemon_core_provider_control_required",
    "rust_daemon_core_provider_inventory_required",
    "agentgres_provider_projection_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "providerId"), false);
  assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
  assert.equal(Object.hasOwn(error.details, "publicCli"), false);
  return true;
}

test("LM Studio driver control and inventory fail closed before public CLI transport", async () => {
  const driver = new LmStudioModelProviderDriver({ state: fakeState() });
  const selectedProvider = provider("/bin/lms");
  const endpoint = {
    id: "endpoint.lmstudio",
    modelId: "model-a",
    backendId: "backend.lmstudio",
    loadPolicy: { mode: "on_demand" },
  };

  assert.equal(Object.hasOwn(Object.getPrototypeOf(driver), "lmsPath"), false);
  assert.equal(Object.hasOwn(Object.getPrototypeOf(driver), "requireLmsPath"), false);

  await assert.rejects(
    () => driver.health(selectedProvider),
    (error) => assertLmStudioCliRetired(error, "provider_health", "model_mount.provider.health"),
  );
  await assert.rejects(
    () => driver.listModels({ provider: selectedProvider }),
    (error) => assertLmStudioCliRetired(error, "provider_models_list", "model_mount.provider.inventory.list_models"),
  );
  await assert.rejects(
    () => driver.listLoaded({ provider: selectedProvider }),
    (error) => assertLmStudioCliRetired(error, "provider_loaded_list", "model_mount.provider.inventory.list_loaded"),
  );
  await assert.rejects(
    () => driver.start({ provider: selectedProvider }),
    (error) => assertLmStudioCliRetired(error, "provider_start", "model_mount.provider.start"),
  );
  await assert.rejects(
    () => driver.stop({ provider: selectedProvider }),
    (error) => assertLmStudioCliRetired(error, "provider_stop", "model_mount.provider.stop"),
  );
  await assert.rejects(
    () => driver.load({ provider: selectedProvider, endpoint, body: { load_options: { context_length: 9999 } } }),
    (error) => {
      assertLmStudioCliRetired(error, "model_load", "model_mount.instance.load");
      assert.equal(error.details.endpoint_id, "endpoint.lmstudio");
      assert.equal(error.details.model_id, "model-a");
      assert.equal(error.details.backend_id, "backend.lmstudio");
      return true;
    },
  );
  await assert.rejects(
    () => driver.unload({ provider: selectedProvider, endpoint }),
    (error) => {
      assertLmStudioCliRetired(error, "model_unload", "model_mount.instance.unload");
      assert.equal(error.details.endpoint_id, "endpoint.lmstudio");
      assert.equal(error.details.model_id, "model-a");
      assert.equal(error.details.backend_id, "backend.lmstudio");
      return true;
    },
  );
});

test("LM Studio driver fails closed for retired JS invocation before CLI transport", async () => {
  const driver = new LmStudioModelProviderDriver({ state: fakeState() });
  const selectedProvider = provider("/bin/lms");
  const endpoint = {
    id: "endpoint.lmstudio",
    modelId: "model-a",
    backendId: "backend.lmstudio",
  };

  await assert.rejects(
    () => driver.invoke({ provider: selectedProvider, endpoint, body: { input: "hello" }, input: "hello" }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "lm_studio" &&
      error.details.stream === false,
  );
  await assert.rejects(
    () => driver.streamInvoke({ provider: selectedProvider, endpoint, body: { input: "hello" } }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.details.provider_kind === "lm_studio" &&
      error.details.stream === true,
  );
  assert.equal(driver.supportsStream("responses"), false);
});
