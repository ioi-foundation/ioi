import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createModelDaemonActions, pickPayloadString } = require("./model-daemon-actions.js");

function createHarness() {
  const requests = [];
  const actions = createModelDaemonActions({
    daemonEndpoint: () => "http://daemon.local",
    daemonToken: () => "token.1",
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return { ok: true, route };
    },
  });
  return { actions, requests };
}

test("payload strings preserve string and numeric command payload aliases", () => {
  assert.equal(pickPayloadString("direct", "value"), "direct");
  assert.equal(pickPayloadString({ modelId: "qwen" }, "modelId"), "qwen");
  assert.equal(pickPayloadString({ limit: 12 }, "limit"), "12");
  assert.equal(pickPayloadString({ value: "ignored" }, "missing"), null);
});

test("model workbench estimate and load use daemon-owned mount payloads", async () => {
  const { actions, requests } = createHarness();

  await actions.runDaemonModelWorkbenchAction("estimate", {
    endpointId: "endpoint.local/model one",
    gpuOffload: "auto",
    contextLength: 8192,
    parallel: 3,
    ttlSeconds: 1200,
  });
  await actions.runDaemonModelWorkbenchAction("load", {
    endpoint_id: "endpoint.local/model one",
    gpu: "24",
  });

  assert.equal(
    requests[0].route,
    "/v1/model-mount/endpoints/endpoint.local%2Fmodel%20one/load",
  );
  assert.deepEqual(requests[0].options.payload, {
    load_options: {
      estimate_only: true,
      gpu: "0",
      context_length: 8192,
      parallel: 3,
      ttl_seconds: 1200,
      identifier: "electron-model-workbench",
    },
  });
  assert.equal(
    requests[1].route,
    "/v1/model-mount/endpoints/endpoint.local%2Fmodel%20one/load",
  );
  assert.deepEqual(requests[1].options.payload.load_policy, {
    mode: "on_demand",
    idle_ttl_seconds: 900,
    auto_evict: true,
  });
  assert.equal(requests[1].options.payload.load_options.gpu, "24");
  assert.equal(requests[1].options.payload.load_options.context_length, 4096);
});

test("model workbench unload prefers instance route when present", async () => {
  const { actions, requests } = createHarness();

  await actions.runDaemonModelWorkbenchAction("unload", {
    endpointId: "endpoint.local/model one",
    instanceId: "instance.loaded/1",
  });

  assert.equal(
    requests[0].route,
    "/v1/model-mount/instances/instance.loaded%2F1/unload",
  );
  assert.deepEqual(requests[0].options.payload, {});
});

test("catalog search and provider configuration preserve daemon route envelopes", async () => {
  const { actions, requests } = createHarness();

  await actions.runDaemonModelCatalogSearch({
    query: "qwen",
    format: "gguf",
    quantization: "Q4_K_M",
    limit: 5,
  });
  await actions.runDaemonModelCatalogProviderConfig({
    providerId: "catalog.local_manifest",
    manifestPath: "/workspace/models.json",
    enabled: false,
  });

  assert.equal(
    requests[0].route,
    "/v1/models/catalog/search?query=qwen&format=gguf&quantization=Q4_K_M&limit=5",
  );
  assert.equal(requests[0].options.method, "GET");
  assert.equal(
    requests[1].route,
    "/v1/model-mount/catalog/providers/catalog.local_manifest",
  );
  assert.deepEqual(requests[1].options.payload, {
    enabled: false,
    manifest_path: "/workspace/models.json",
  });
});

test("catalog download requires source url and gates external network by daemon policy", async () => {
  const { actions, requests } = createHarness();

  await assert.rejects(
    () => actions.runDaemonModelCatalogDownload({ modelId: "qwen" }),
    /catalog source URL/,
  );
  await actions.runDaemonModelCatalogDownload({
    source_url: "https://huggingface.co/example/model.gguf",
    model_id: "qwen",
    catalogEntryId: "catalog.1",
  });

  assert.equal(requests[0].route, "/v1/model-mount/downloads");
  assert.deepEqual(requests[0].options.payload, {
    source_url: "https://huggingface.co/example/model.gguf",
    model_id: "qwen",
    catalog_entry_id: "catalog.1",
    download_policy: {
      approvalDecision: "required",
      externalNetwork: "daemon_gated",
    },
  });
});

test("missing daemon endpoint fails closed before model command actions", async () => {
  const actions = createModelDaemonActions({
    daemonEndpoint: () => "",
    daemonToken: () => "token.1",
    requestJson: async () => {
      throw new Error("request should not run");
    },
  });

  await assert.rejects(
    () => actions.runDaemonModelCatalogSearch({ query: "qwen" }),
    /IOI_DAEMON_ENDPOINT/,
  );
});
