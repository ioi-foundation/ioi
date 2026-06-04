import assert from "node:assert/strict";
import test from "node:test";

import { driverForProvider } from "./provider-driver-factory.mjs";

test("provider driver factory preserves concrete driver routing", () => {
  const state = { nowIso: () => "2026-06-03T00:00:00.000Z" };

  assert.equal(driverForProvider(state, { kind: "ioi_native_local" }).constructor.name, "NativeLocalModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "lm_studio" }).constructor.name, "LmStudioModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "llama_cpp" }).constructor.name, "LlamaCppModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "ollama" }).constructor.name, "OllamaModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "vllm" }).constructor.name, "VllmModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "openai" }).constructor.name, "OpenAICompatibleModelProviderDriver");
  assert.equal(driverForProvider(state, { kind: "unknown" }).constructor.name, "FixtureModelProviderDriver");
});

test("provider driver factory gives stateful drivers the mounting state", () => {
  const state = { nowIso: () => "2026-06-03T00:00:00.000Z" };

  assert.equal(driverForProvider(state, { kind: "lm_studio" }).state, state);
  assert.equal(driverForProvider(state, { kind: "llama_cpp" }).state, state);
  assert.equal(driverForProvider(state, { kind: "vllm" }).state, state);
});

test("provider driver factory preserves explicit driver overrides", () => {
  const state = { nowIso: () => "2026-06-03T00:00:00.000Z" };

  assert.equal(
    driverForProvider(state, { kind: "openai", driver: "fixture" }).constructor.name,
    "FixtureModelProviderDriver",
  );
  assert.equal(
    driverForProvider(state, { kind: "custom_http", driver: "openai_compatible" }).constructor.name,
    "OpenAICompatibleModelProviderDriver",
  );
});
