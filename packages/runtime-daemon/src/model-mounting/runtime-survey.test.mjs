import assert from "node:assert/strict";
import test from "node:test";

import {
  latestRuntimeSurvey,
  lmStudioRuntimeEngines,
  lmStudioRuntimeSurvey,
  runtimeSurvey,
} from "./runtime-survey.mjs";

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
    listRuntimeEngines() {
      return [
        { id: "engine_a", selected: true },
        { id: "engine_b", selected: false },
      ];
    },
    lmStudioRuntimeSurvey(checkedAt) {
      return { status: "available", checkedAt, selectedRuntime: "llama.cpp" };
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
    runtimePreference() {
      return { selectedEngineId: "engine_a" };
    },
  };
  return state;
}

const deps = {
  hardwareSnapshot: () => ({ cpuCount: 8 }),
  isExecutable: (filePath) => filePath === "/bin/lms",
  lmStudioRuntimeDiscoveryEnabled: () => true,
  parseLmStudioRuntimeEngines: () => [{ id: "lmstudio.runtime.llama.cpp", selected: true }],
  parseLmStudioRuntimeSurvey: () => ({
    selectedRuntime: "llama.cpp",
    accelerators: [{ label: "GPU", vram: "24 GB" }],
    cpu: "Ryzen",
    ram: "64 GB",
  }),
  runPublicCommand: (_command, args) => args.includes("ls")
    ? { status: 0, stdout: "runtime ls", stderr: "", error: null }
    : { status: 0, stdout: "runtime survey", stderr: "", error: null },
  schemaVersion: "schema.v1",
  stableHash: (value) => `hash:${value}`,
};

test("runtimeSurvey facade fails closed before JS probes, engine reads, or receipt creation", () => {
  const state = fakeState();
  let hardwareCalls = 0;
  let engineCalls = 0;
  let lmStudioCalls = 0;
  state.listRuntimeEngines = () => {
    engineCalls += 1;
    return [{ id: "engine_a", selected: true }];
  };
  state.lmStudioRuntimeSurvey = () => {
    lmStudioCalls += 1;
    return { status: "available" };
  };

  assert.throws(
    () => runtimeSurvey(state, {
      ...deps,
      hardwareSnapshot: () => {
        hardwareCalls += 1;
        return { cpuCount: 8 };
      },
    }),
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

test("latestRuntimeSurvey reports not-checked state and checked receipts", () => {
  const state = fakeState();

  assert.deepEqual(latestRuntimeSurvey(state, deps), {
    status: "not_checked",
    receiptId: "none",
    checkedAt: null,
    engineCount: 2,
    selectedEngines: [],
    runtimePreference: { selectedEngineId: "engine_a" },
    hardware: { cpuCount: 8 },
    lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
  });

  state.receipts.push({
    id: "receipt_1",
    kind: "runtime_survey",
    createdAt: "2026-06-03T12:00:00.000Z",
    details: {
      checked_at: "2026-06-03T12:00:00.000Z",
      engine_count: 2,
      selected_engines: ["engine_a"],
      runtime_preference: { selectedEngineId: "engine_a" },
      hardware: { cpuCount: 8 },
      lm_studio: { status: "available" },
    },
  });
  const latest = latestRuntimeSurvey(state, deps);

  assert.equal(latest.status, "checked");
  assert.equal(latest.receiptId, "receipt_1");
  assert.equal(latest.engineCount, 2);
  assert.deepEqual(latest.selectedEngines, ["engine_a"]);
  assert.equal(Object.hasOwn(state.receipts[0].details, "checkedAt"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "engineCount"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "selectedEngines"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "runtimePreference"), false);
  assert.equal(Object.hasOwn(state.receipts[0].details, "lmStudio"), false);
});

test("lmStudioRuntimeEngines returns hashed public runtime list records", () => {
  const state = fakeState();

  const engines = lmStudioRuntimeEngines(state, "2026-06-03T12:00:00.000Z", deps);

  assert.deepEqual(engines, [{
    id: "lmstudio.runtime.llama.cpp",
    selected: true,
    checkedAt: "2026-06-03T12:00:00.000Z",
    lmsPathHash: "hash:/bin/lms",
    outputHash: "hash:runtime ls",
    evidenceRefs: ["lm_studio_public_lms_runtime_ls"],
  }]);
});

test("LM Studio runtime probes are absent when disabled or executable is missing", () => {
  const state = fakeState();

  assert.deepEqual(lmStudioRuntimeEngines(state, "now", {
    ...deps,
    lmStudioRuntimeDiscoveryEnabled: () => false,
  }), []);
  assert.deepEqual(lmStudioRuntimeSurvey(state, "now", {
    ...deps,
    lmStudioRuntimeDiscoveryEnabled: () => false,
  }), {
    status: "absent",
    checkedAt: "now",
    evidenceRefs: ["lm_studio_public_runtime_discovery_disabled"],
  });
  assert.deepEqual(lmStudioRuntimeSurvey(state, "now", {
    ...deps,
    isExecutable: () => false,
  }), {
    status: "absent",
    checkedAt: "now",
    evidenceRefs: ["lm_studio_public_lms_absent"],
  });
});

test("LM Studio runtime survey records blocked command failures without raw stderr", () => {
  const state = fakeState();

  const survey = lmStudioRuntimeSurvey(state, "2026-06-03T12:00:00.000Z", {
    ...deps,
    runPublicCommand: () => ({ status: 7, stdout: "", stderr: "secret failure", error: null }),
  });

  assert.equal(survey.status, "blocked");
  assert.equal(survey.exitCode, 7);
  assert.equal(survey.errorHash, "hash:secret failure");
  assert.equal("stderr" in survey, false);
});
