import test from "node:test";
import assert from "node:assert/strict";

import {
  defaultBackendForProvider,
  firstFiniteNumber,
  modelInvocationCoalesceKey,
  modelInvocationIsLowVariance,
  providerBodyWithoutGeneratedResponseIds,
  supportsResponseState,
} from "./provider-driver-helpers.mjs";

test("provider backend helper maps product providers to Rust backend ids", () => {
  assert.equal(defaultBackendForProvider({ kind: "ioi_native_local" }), "backend.autopilot.native-local.fixture");
  assert.equal(defaultBackendForProvider({ kind: "llama_cpp" }), "backend.llama-cpp");
  assert.equal(defaultBackendForProvider({ kind: "gemini" }), "backend.openai-compatible");
  assert.equal(defaultBackendForProvider({ kind: "fixture" }), "backend.fixture");
});

test("response state support is limited to stateful text protocols", () => {
  assert.equal(supportsResponseState("chat"), true);
  assert.equal(supportsResponseState("responses"), true);
  assert.equal(supportsResponseState("messages"), true);
  assert.equal(supportsResponseState("embeddings"), false);
  assert.equal(supportsResponseState("rerank"), false);
});

test("coalesce keys are stable for low-variance requests and ignore generated response ids", () => {
  const base = {
    kind: "chat",
    body: { model: "route.local", temperature: 0.1, model_policy: { locality: "local-first" } },
    providerBody: { messages: [{ role: "user", content: "hello" }], response_id: "generated-1" },
    input: "hello",
    token: { grantId: "grant-1" },
    selection: {
      route: { id: "route-1" },
      endpoint: { id: "endpoint-1", providerId: "provider-1", modelId: "model-1" },
      provider: { id: "provider-1" },
    },
  };
  const first = modelInvocationCoalesceKey(base);
  const second = modelInvocationCoalesceKey({
    ...base,
    providerBody: { ...base.providerBody, response_id: "generated-2", responseId: "generated-3" },
  });

  assert.equal(typeof first, "string");
  assert.equal(first, second);
  assert.equal(first.includes("hello"), false);
  assert.equal(first.includes("generated"), false);
});

test("coalesce keys ignore retired modelPolicy policy alias", () => {
  const base = {
    kind: "chat",
    body: { model: "route.local", temperature: 0.1 },
    providerBody: { messages: [{ role: "user", content: "hello" }] },
    input: "hello",
    token: { grantId: "grant-1" },
    selection: {
      route: { id: "route-1" },
      endpoint: { id: "endpoint-1", providerId: "provider-1", modelId: "model-1" },
      provider: { id: "provider-1" },
    },
  };

  const withoutPolicy = modelInvocationCoalesceKey(base);
  const legacyPolicy = modelInvocationCoalesceKey({
    ...base,
    body: { ...base.body, modelPolicy: { locality: "legacy-local-first" } },
  });
  const canonicalPolicy = modelInvocationCoalesceKey({
    ...base,
    body: { ...base.body, model_policy: { locality: "local-first" } },
  });

  assert.equal(legacyPolicy, withoutPolicy);
  assert.notEqual(canonicalPolicy, withoutPolicy);
});

test("coalesce keys reject streaming, stateful follow-ups, tools, embeddings, and high variance", () => {
  const base = {
    kind: "chat",
    body: { temperature: 0 },
    providerBody: {},
    input: "hello",
  };

  assert.equal(modelInvocationCoalesceKey({ ...base, body: { stream: true } }), null);
  assert.equal(modelInvocationCoalesceKey({ ...base, previousResponseId: "resp-1" }), null);
  assert.equal(modelInvocationCoalesceKey({ ...base, providerBody: { tools: [{}] } }), null);
  assert.equal(modelInvocationCoalesceKey({ ...base, kind: "embeddings" }), null);
  assert.equal(modelInvocationCoalesceKey({ ...base, providerBody: { temperature: 0.7 } }), null);
  assert.equal(modelInvocationCoalesceKey({ ...base, providerBody: { top_p: 0.8 } }), null);
});

test("variance and provider-body helpers preserve numeric and generated-id semantics", () => {
  assert.equal(modelInvocationIsLowVariance({ options: { temperature: "0.2" } }, {}), true);
  assert.equal(modelInvocationIsLowVariance({ sendOptions: { temperature: "0.21" } }, {}), false);
  assert.equal(modelInvocationIsLowVariance({ topP: "0.95" }, {}), true);
  assert.equal(modelInvocationIsLowVariance({ topP: "0.94" }, {}), false);

  assert.equal(firstFiniteNumber([null, "", "nope", "4.5"]), 4.5);
  assert.deepEqual(providerBodyWithoutGeneratedResponseIds({
    response_id: "resp-1",
    responseId: "resp-2",
    messages: [],
  }), { messages: [] });
  assert.deepEqual(providerBodyWithoutGeneratedResponseIds(["not", "object"]), ["not", "object"]);
});
