import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

async function withModelState(fn) {
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
  });
  try {
    return await fn(state);
  } finally {
    state.close();
  }
}

function mountTestModel(state) {
  state.upsertProvider({
    id: "provider.test",
    kind: "openai_compatible",
    label: "test",
    driver: "openai_compatible",
    api_format: "openai",
    base_url: "http://127.0.0.1:1",
    capabilities: ["chat"],
    status: "configured",
  });
  state.importModel({ model_id: "test-model", provider_id: "provider.test" });
  state.mountEndpoint({
    id: "endpoint.test",
    model_id: "test-model",
    provider_id: "provider.test",
  });
}

test("identical low-variance in-flight chat invocations share one provider call", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpointId: endpoint.id,
      backendId: "backend.test",
    });
    let providerCalls = 0;
    state.driverForProvider = () => ({
      invoke: async () => {
        providerCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          outputText: "ok",
          tokenCount: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          providerResponseKind: null,
        };
      },
    });
    const token = state.createToken({
      allowed: ["model.chat:*", "route.use:*"],
      denied: [],
    }).token;
    const body = {
      model: "test-model",
      route_id: "route.local-first",
      messages: [{ role: "user", content: "choose the next action" }],
      temperature: 0.1,
    };

    const [first, second] = await Promise.all([
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
    ]);

    assert.equal(providerCalls, 1);
    assert.equal(first.outputText, "ok");
    assert.equal(second.outputText, "ok");
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation_coalesced");
    assert.equal(second.receipt.details.coalesced, true);
  });
});

test("high-variance chat invocations are not coalesced", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpointId: endpoint.id,
      backendId: "backend.test",
    });
    let providerCalls = 0;
    state.driverForProvider = () => ({
      invoke: async () => {
        providerCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          outputText: `ok ${providerCalls}`,
          tokenCount: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          providerResponseKind: null,
        };
      },
    });
    const token = state.createToken({
      allowed: ["model.chat:*", "route.use:*"],
      denied: [],
    }).token;
    const body = {
      model: "test-model",
      route_id: "route.local-first",
      messages: [{ role: "user", content: "draft a creative variation" }],
      temperature: 0.8,
    };

    const [first, second] = await Promise.all([
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
    ]);

    assert.equal(providerCalls, 2);
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation");
  });
});
