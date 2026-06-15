import assert from "node:assert/strict";
import test from "node:test";

import * as runtimeProfile from "./runtime-api-bridge.mjs";

const {
  isFixtureRuntimeProfile,
  isRuntimeServiceProfile,
  normalizeRuntimeProfile,
  runtimeProfileForRequest,
} = runtimeProfile;

test("runtime profile request normalization accepts canonical profile fields", () => {
  assert.equal(runtimeProfileForRequest({ runtime_profile: "runtime" }), "runtime_service");
  assert.equal(runtimeProfileForRequest({}, { runtime_profile: "live" }), "runtime_service");
  assert.equal(runtimeProfileForRequest({ runtime_profile: "fixture" }), "fixture");
  assert.equal(normalizeRuntimeProfile("agentgres_fixture"), "fixture");
  assert.equal(isRuntimeServiceProfile("production"), true);
  assert.equal(isFixtureRuntimeProfile("local_daemon_agentgres_projection"), true);
});

test("runtime profile request normalization ignores retired camelCase aliases", () => {
  assert.equal(runtimeProfileForRequest({ runtimeProfile: "runtime" }), "fixture");
  assert.equal(runtimeProfileForRequest({}, { runtimeProfile: "runtime" }), "fixture");
  assert.equal(
    runtimeProfileForRequest(
      { runtimeProfile: "runtime" },
      { runtime_profile: "fixture" },
    ),
    "fixture",
  );
});

test("runtime service adapter surface is retired", () => {
  const retiredExports = [
    ["create", "Runtime", "Api", "Bridge"].join(""),
    ["Runtime", "Api", "Bridge"].join(""),
    ["Runtime", "Api", "Bridge", "Unavailable", "Error"].join(""),
  ];
  for (const exportName of retiredExports) {
    assert.equal(Object.hasOwn(runtimeProfile, exportName), false);
  }
  assert.equal(runtimeProfileForRequest({ runtime_profile: "runtime" }), "runtime_service");
});
