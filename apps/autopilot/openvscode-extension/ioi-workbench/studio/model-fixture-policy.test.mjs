import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioModelFixturePolicy } = require("./model-fixture-policy.js");

function createPolicy(env = {}) {
  return createStudioModelFixturePolicy({
    getEnv: (name) => env[name],
    stringValue: (value, fallback = "") => {
      if (typeof value !== "string") return fallback;
      const trimmed = value.trim();
      return trimmed || fallback;
    },
  });
}

test("model fixture policy keeps fixture model usage gated by environment", () => {
  assert.equal(createPolicy().studioFixtureModelUsageAllowed(), false);
  assert.deepEqual(createPolicy().studioDenyFixtureModelPolicy(), {
    deny_fixture_models: true,
    denyFixtureModels: true,
  });

  const explicitAllow = createPolicy({ IOI_STUDIO_ALLOW_FIXTURE_MODELS: "true" });
  assert.equal(explicitAllow.studioFixtureModelUsageAllowed(), true);
  assert.deepEqual(explicitAllow.studioDenyFixtureModelPolicy(), {});

  const legacyAllow = createPolicy({ IOI_STUDIO_FIXTURE_MODE: "on" });
  assert.equal(legacyAllow.studioFixtureModelUsageAllowed(), true);
});

test("model fixture policy detects product fixture markers", () => {
  const policy = createPolicy();

  for (const text of [
    "IOI model router fixture response",
    "input_hash=abc123",
    "autopilot:native-fixture",
    "local:auto",
    "stories260k",
    "deterministic native-local model fixture",
    "native_local.fixture",
    "backend.fixture",
  ]) {
    assert.equal(policy.studioTextContainsProductFixtureMarker(text), true, text);
  }

  assert.equal(policy.studioTextContainsProductFixtureMarker("qwen/qwen3.5-9b local product model"), false);
});
