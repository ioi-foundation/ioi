import assert from "node:assert/strict";
import test from "node:test";

import {
  ModelMountingState,
} from "../model-mounting.mjs";

function fakeState() {
  const state = {
    homeDir: "/home/ioi",
    providers: new Map([
      ["provider.lmstudio", {
        id: "provider.lmstudio",
        discovery: { publicCli: { path: "/bin/lms" } },
      }],
    ]),
    receipts: [],
    listReceipts() {
      return this.receipts;
    },
    nowIso() {
      return "2026-06-03T12:00:00.000Z";
    },
    receipt(kind, payload) {
      const receipt = {
        id: `receipt_${this.receipts.length + 1}`,
        kind,
        createdAt: "2026-06-03T12:00:00.000Z",
        details: payload.details,
      };
      this.receipts.push(receipt);
      return receipt;
    },
  };
  return state;
}

test("runtimeSurvey facade fails closed before JS probes, engine reads, or receipt creation", () => {
  const state = fakeState();
  let hardwareCalls = 0;
  let engineCalls = 0;
  let lmStudioCalls = 0;
  state.hardwareSnapshot = () => {
    hardwareCalls += 1;
    return { cpuCount: 8 };
  };
  state.listRuntimeEngines = () => {
    engineCalls += 1;
    return [{ id: "engine_a", selected: true }];
  };
  state.lmStudioRuntimeSurvey = () => {
    lmStudioCalls += 1;
    return { status: "available" };
  };

  assert.throws(
    () => ModelMountingState.prototype.runtimeSurvey.call(state),
    (error) => {
      assert.equal(error.code, "model_mount_runtime_survey_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "model_mount.runtime_survey");
      assert.equal(error.details.operation, "runtime_survey");
      assert.equal(error.details.operation_kind, "model_mount.runtime_survey.capture");
      assert.deepEqual(error.details.evidence_refs, [
        "model_mount_runtime_survey_js_facade_retired",
        "rust_daemon_core_runtime_survey_required",
        "agentgres_runtime_survey_projection_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "checkedAt"), false);
      assert.equal(Object.hasOwn(error.details, "engineCount"), false);
      assert.equal(Object.hasOwn(error.details, "selectedEngines"), false);
      assert.equal(Object.hasOwn(error.details, "runtimePreference"), false);
      assert.equal(Object.hasOwn(error.details, "lmStudio"), false);
      return true;
    },
  );

  assert.equal(hardwareCalls, 0);
  assert.equal(engineCalls, 0);
  assert.equal(lmStudioCalls, 0);
  assert.deepEqual(state.receipts, []);
});
