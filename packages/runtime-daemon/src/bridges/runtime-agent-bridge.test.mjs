import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertRuntimeBridgeAvailable,
  runtimeBridgeUnavailable,
} from "./runtime-agent-bridge.mjs";

function deps() {
  return {
    externalBlocker(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
  };
}

test("runtime bridge availability accepts supported operations", () => {
  const runtimeBridge = {
    canStartThread: true,
    canSubmitTurn: true,
    canInspectThread: true,
    canControlThread: true,
  };

  for (const operation of ["start_thread", "submit_turn", "inspect_thread", "control_thread"]) {
    assert.doesNotThrow(() =>
      assertRuntimeBridgeAvailable(runtimeBridge, { runtimeProfile: "runtime_service", operation }, deps()),
    );
  }
});

test("runtime bridge availability rejects unsupported operations with external blocker details", () => {
  assert.throws(
    () => assertRuntimeBridgeAvailable({}, { runtimeProfile: "runtime_service", operation: "submit_turn" }, deps()),
    (error) => {
      assert.equal(error.message, "RuntimeAgentService bridge is required for runtime_service profile.");
      assert.equal(error.details.runtimeProfile, "runtime_service");
      assert.equal(error.details.operation, "submit_turn");
      assert.equal(error.details.requiredBridge, "RuntimeApiBridge");
      assert.equal(error.details.syntheticFallbackAllowed, false);
      return true;
    },
  );
});

test("runtime bridge unavailable merges adapter details", () => {
  const error = runtimeBridgeUnavailable({
    runtimeProfile: "runtime_service",
    operation: "control_thread",
    details: { adapterErrorCode: "not_configured" },
  }, deps());

  assert.equal(error.details.operation, "control_thread");
  assert.equal(error.details.adapterErrorCode, "not_configured");
  assert.equal(error.details.fixtureProfile, "fixture");
});
