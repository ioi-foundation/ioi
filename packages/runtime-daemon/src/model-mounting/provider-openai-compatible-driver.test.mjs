import assert from "node:assert/strict";
import test from "node:test";

import { OpenAICompatibleModelProviderDriver } from "./provider-openai-compatible-driver.mjs";

function provider() {
  return {
    id: "provider.compat",
    kind: "openai_compatible",
    baseUrl: "http://127.0.0.1:65535",
    status: "configured",
    apiFormat: "openai_compatible",
    privacyClass: "workspace",
    capabilities: ["chat", "responses", "embeddings"],
    authScheme: "none",
  };
}

function endpoint() {
  return {
    id: "endpoint.compat",
    providerId: "provider.compat",
    modelId: "chat-a",
    apiFormat: "openai_compatible",
  };
}

function assertProviderHttpTransportRetired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_provider_http_transport_retired");
  assert.equal(error.details.provider_id, "provider.compat");
  assert.equal(error.details.provider_kind, "openai_compatible");
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

test("OpenAI-compatible driver health and inventory fail before HTTP request shaping", async () => {
  const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });
  const selectedProvider = provider();

  await assert.rejects(
    () => driver.health(selectedProvider, { state: null }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_health.compat"),
  );
  await assert.rejects(
    () => driver.listModels({ provider: selectedProvider, state: null }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_inventory.compat"),
  );
});

test("OpenAI-compatible driver lifecycle fails before stateless JS load projection", async () => {
  const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });

  await assert.rejects(
    () => driver.load({ endpoint: endpoint() }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_lifecycle.compat_load"),
  );
  await assert.rejects(
    () => driver.unload({ endpoint: endpoint() }),
    (error) => assertProviderHttpTransportRetired(error, "model_mount.provider_lifecycle.compat_unload"),
  );
});

test("OpenAI-compatible driver invocation fails closed before HTTP request shaping", async () => {
  const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });
  await assert.rejects(
    () =>
      driver.invoke({
        provider: provider(),
        endpoint: endpoint(),
        kind: "responses",
        body: { input: "hello" },
        input: "hello",
        state: null,
      }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.status === 501 &&
      error.details.provider_kind === "openai_compatible" &&
      error.details.stream === false,
  );
});

test("OpenAI-compatible driver stream invocation fails closed before HTTP request shaping", async () => {
  const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });
  await assert.rejects(
    () =>
      driver.streamInvoke({
        provider: provider(),
        endpoint: endpoint(),
        kind: "responses",
        body: { input: "hello" },
        state: null,
      }),
    (error) =>
      error.code === "model_mount_provider_js_invocation_retired" &&
      error.status === 501 &&
      error.details.provider_kind === "openai_compatible" &&
      error.details.stream === true,
  );

  assert.equal(driver.supportsStream("responses"), false);
});
