import assert from "node:assert/strict";
import test from "node:test";

import { OllamaModelProviderDriver } from "./provider-ollama-driver.mjs";

function provider() {
  return {
    id: "provider.ollama",
    kind: "ollama",
    baseUrl: "http://127.0.0.1:65535",
    status: "configured",
    authScheme: "none",
  };
}

function endpoint() {
  return {
    id: "endpoint.ollama",
    modelId: "qwen:test",
    apiFormat: "ollama",
    loadPolicy: { mode: "on_demand" },
  };
}

function fakeState({ binaryPath = null } = {}) {
  const backend = { id: "backend.ollama", kind: "ollama", binaryPath };
  return {
    backend(backendId) {
      assert.equal(backendId, "backend.ollama");
      return backend;
    },
  };
}

function assertProviderHttpTransportRetired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_provider_http_transport_retired");
  assert.equal(error.details.provider_id, "provider.ollama");
  assert.equal(error.details.provider_kind, "ollama");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.provider_transport");
  assert.deepEqual(error.details.evidence_refs, [
    "provider_http_transport_js_retired",
    "rust_daemon_core_provider_transport_required",
    "agentgres_provider_projection_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "providerId"), false);
  assert.equal(Object.hasOwn(error.details, "providerKind"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

test("Ollama driver health and inventory fail before HTTP request shaping", async () => {
  const state = fakeState();
  const driver = new OllamaModelProviderDriver();
  const selectedProvider = provider();

  await assert.rejects(
    () => driver.health(selectedProvider, { state }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_health.ollama"),
  );
  await assert.rejects(
    () => driver.listModels({ provider: selectedProvider, state }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_inventory.ollama_models"),
  );
  await assert.rejects(
    () => driver.listLoaded({ provider: selectedProvider, state }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_inventory.ollama_loaded"),
  );
});

test("Ollama lifecycle without binary fails before HTTP keep-alive request shaping", async () => {
  const state = fakeState();
  const driver = new OllamaModelProviderDriver();
  const selectedProvider = provider();
  const selectedEndpoint = endpoint();

  await assert.rejects(
    () => driver.load({ state, provider: selectedProvider, endpoint: selectedEndpoint, body: { ttl_seconds: 60 } }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_lifecycle.ollama_load"),
  );
  await assert.rejects(
    () => driver.unload({ state, provider: selectedProvider, endpoint: selectedEndpoint }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_lifecycle.ollama_unload"),
  );
});

test("Ollama lifecycle with binary still fails before JS process staging", async () => {
  const state = fakeState({ binaryPath: "/usr/bin/ollama" });
  const driver = new OllamaModelProviderDriver();

  await assert.rejects(
    () => driver.load({ state, provider: provider(), endpoint: endpoint(), body: { ttl_seconds: 60 } }),
    (error) =>
      error.code === "model_mount_backend_process_supervisor_retired" &&
      error.details.operation_kind === "model_mount.provider_lifecycle.ollama_load",
  );
});

test("Ollama driver fails closed for retired JS invocation before HTTP request shaping", async () => {
  const state = fakeState();
  const driver = new OllamaModelProviderDriver();
  const selectedProvider = provider();

  await assert.rejects(
    () =>
      driver.invoke({
        state,
        provider: selectedProvider,
        endpoint: endpoint(),
        kind: "chat.completions",
        body: { messages: [{ role: "user", content: "hello" }] },
        input: "hello",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_js_invocation_retired");
      assert.equal(error.details.provider_kind, "ollama");
      assert.equal(error.details.provider_driver, "ollama");
      assert.equal(error.details.stream, false);
      return true;
    },
  );

  await assert.rejects(
    () =>
      driver.streamInvoke({
        state,
        provider: selectedProvider,
        endpoint: endpoint(),
        kind: "chat.completions",
        body: { messages: [{ role: "user", content: "hello" }] },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_js_invocation_retired");
      assert.equal(error.details.provider_kind, "ollama");
      assert.equal(error.details.stream, true);
      return true;
    },
  );

  assert.equal(driver.supportsStream("chat.completions"), false);
});
