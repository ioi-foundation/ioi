import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { OllamaModelProviderDriver } from "./provider-ollama-driver.mjs";

async function withOllamaServer(handler) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const body = bodyText ? JSON.parse(bodyText) : null;
    requests.push({ method: request.method, url: request.url, body });

    if (request.url === "/api/tags") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ models: [{ name: "qwen:test" }] }));
      return;
    }
    if (request.url === "/api/ps") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ models: [{ name: "qwen:test", size: 4096, processor: "cpu", expires_at: "2026-06-03T00:00:00.000Z" }] }));
      return;
    }
    if (request.url === "/api/generate") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ done: true }));
      return;
    }
    if (request.url === "/api/embeddings") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ embedding: [0.1, 0.2, 0.3] }));
      return;
    }
    if (request.url === "/api/chat") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ message: { role: "assistant", content: "ollama says hi" } }));
      return;
    }

    response.writeHead(404, { "content-type": "application/json" });
    response.end("{}");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    return await handler({ baseUrl: `http://127.0.0.1:${address.port}`, requests });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function provider(baseUrl) {
  return {
    id: "provider.ollama",
    kind: "ollama",
    baseUrl,
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

function fakeState() {
  const backend = { id: "backend.ollama", binaryPath: null };
  return {
    backend(backendId) {
      assert.equal(backendId, "backend.ollama");
      return backend;
    },
    backendProcessForBackend() {
      return null;
    },
    backendProcessSnapshot(record) {
      return record ? { id: record.id } : null;
    },
    listInstances() {
      return [];
    },
  };
}

test("Ollama driver lists available and loaded models", async () => {
  await withOllamaServer(async ({ baseUrl }) => {
    const state = fakeState();
    const driver = new OllamaModelProviderDriver();
    const models = await driver.listModels({ provider: provider(baseUrl), state });
    const loaded = await driver.listLoaded({ provider: provider(baseUrl), state });

    assert.equal(models.length, 1);
    assert.equal(models[0].id, "ollama.qwen.test");
    assert.equal(models[0].modelId, "qwen:test");
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].backend, "ollama");
    assert.equal(loaded[0].backendId, "backend.ollama");
  });
});

test("Ollama driver invokes chat, embeddings, load, and unload probes", async () => {
  await withOllamaServer(async ({ baseUrl, requests }) => {
    const state = fakeState();
    const driver = new OllamaModelProviderDriver();
    const selectedProvider = provider(baseUrl);
    const selectedEndpoint = endpoint();

    const load = await driver.load({
      state,
      provider: selectedProvider,
      endpoint: selectedEndpoint,
      body: {
        ttl_seconds: 60,
        loadOptions: { idle_ttl_seconds: 999 },
        ttlSeconds: 888,
        contextLength: 7777,
      },
    });
    assert.equal(load.status, "loaded");
    assert.equal(load.providerStatus, "warmed");

    const chat = await driver.invoke({
      state,
      provider: selectedProvider,
      endpoint: selectedEndpoint,
      kind: "chat.completions",
      body: { messages: [{ role: "user", content: "hello" }] },
      input: "hello",
    });
    assert.equal(chat.outputText, "ollama says hi");
    assert.equal(chat.providerResponseKind, "ollama.chat");

    const embedding = await driver.invoke({
      state,
      provider: selectedProvider,
      endpoint: selectedEndpoint,
      kind: "embeddings",
      body: { input: "hello" },
      input: "hello",
    });
    assert.equal(embedding.providerResponseKind, "embeddings");
    assert.deepEqual(embedding.providerResponse.data[0].embedding, [0.1, 0.2, 0.3]);

    const unload = await driver.unload({ state, provider: selectedProvider, endpoint: selectedEndpoint });
    assert.equal(unload.status, "unloaded");
    assert.equal(unload.providerStatus, "evicted");

    assert.ok(requests.some((request) => request.url === "/api/chat"));
    assert.equal(requests.filter((request) => request.url === "/api/generate").length, 2);
    assert.equal(requests.find((request) => request.url === "/api/generate").body.keep_alive, "60s");
  });
});
