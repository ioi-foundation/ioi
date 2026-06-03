import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { OpenAICompatibleModelProviderDriver } from "./provider-openai-compatible-driver.mjs";

async function withOpenAiCompatibleServer(handler) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const body = bodyText ? JSON.parse(bodyText) : null;
    requests.push({ method: request.method, url: request.url, body });

    if (request.url === "/models") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ data: [{ id: "chat-a" }] }));
      return;
    }
    if (request.url === "/responses") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "not_found", message: "responses unavailable" } }));
      return;
    }
    if (request.url === "/chat/completions") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        id: "chatcmpl-test",
        choices: [{ message: { role: "assistant", content: "hello from compatible chat" } }],
        usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 },
      }));
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
    id: "provider.compat",
    kind: "openai_compatible",
    baseUrl,
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

test("OpenAI-compatible driver lists and invokes chat completion models", async () => {
  await withOpenAiCompatibleServer(async ({ baseUrl, requests }) => {
    const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });
    const models = await driver.listModels({ provider: provider(baseUrl), state: null });

    assert.equal(models.length, 1);
    assert.equal(models[0].id, "provider.compat.chat.a");
    assert.equal(models[0].family, "compat");

    const result = await driver.invoke({
      provider: provider(baseUrl),
      endpoint: endpoint(),
      kind: "chat.completions",
      body: { messages: [{ role: "user", content: "hello" }] },
      input: "hello",
      state: null,
    });

    assert.equal(result.outputText, "hello from compatible chat");
    assert.equal(result.providerResponseKind, "chat.completions");
    assert.equal(result.backendId, "backend.openai-compatible");
    assert.equal(result.tokenCount.totalTokens ?? result.tokenCount.total_tokens, 7);
    assert.ok(requests.some((request) => request.url === "/models"));
    assert.ok(requests.some((request) => request.url === "/chat/completions"));
  });
});

test("OpenAI-compatible driver falls back from responses to chat completions", async () => {
  await withOpenAiCompatibleServer(async ({ baseUrl, requests }) => {
    const driver = new OpenAICompatibleModelProviderDriver({ label: "compat" });
    const result = await driver.invoke({
      provider: provider(baseUrl),
      endpoint: endpoint(),
      kind: "responses",
      body: { input: "hello" },
      input: "hello",
      state: null,
    });

    assert.equal(result.outputText, "hello from compatible chat");
    assert.equal(result.providerResponseKind, "chat.completions");
    assert.equal(result.compatTranslation, "chat_completions");
    assert.deepEqual(requests.map((request) => request.url), ["/responses", "/chat/completions"]);
  });
});
