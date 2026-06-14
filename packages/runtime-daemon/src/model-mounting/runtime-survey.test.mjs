import assert from "node:assert/strict";
import test from "node:test";

import {
  ModelMountingState,
} from "../model-mounting.mjs";

function runtimeSurveyPlan(request) {
  return {
    source: "rust_model_mount_runtime_survey_command",
    backend: "rust_model_mount_runtime_survey",
    public_response: {
      schemaVersion: "ioi.model-mounting.runtime.v1",
      object: "ioi.model_mount_runtime_survey",
      status: "checked",
      receiptId: "receipt_runtime_survey_test",
      checkedAt: request.generated_at,
      engineCount: 1,
      engines: [{ id: "backend.llama-cpp", selected: true }],
      selectedEngines: [{ id: "backend.llama-cpp", selected: true }],
      selectedEngineIds: ["backend.llama-cpp"],
      runtimePreference: { selected_engine_id: "backend.llama-cpp" },
      hardware: {
        status: "checked",
        cpuCount: 8,
        totalMemoryBytes: 1024,
        jsProbeExecution: false,
      },
      lmStudio: { status: "not_checked", jsCliExecution: false },
      rustCoreBoundary: "model_mount.runtime_survey",
      operationKind: request.operation_kind,
      surveyHash: "sha256:runtime-survey",
      jsHardwareProbeExecuted: false,
      jsRuntimeEngineReadExecuted: false,
      jsLmStudioProbeExecuted: false,
      evidenceRefs: [
        "model_mount_runtime_survey_js_facade_retired",
        "rust_daemon_core_runtime_survey",
        "agentgres_runtime_survey_truth_required",
        "rust_model_mount_core",
      ],
    },
    receipt: {
      id: "receipt_runtime_survey_test",
      kind: "runtime_survey",
      schemaVersion: "ioi.model-mounting.runtime.v1",
      createdAt: request.generated_at,
      redaction: "redacted",
      evidenceRefs: [
        "model_mount_runtime_survey_js_facade_retired",
        "rust_daemon_core_runtime_survey",
        "agentgres_runtime_survey_truth_required",
        "rust_model_mount_core",
      ],
      details: {
        checked_at: request.generated_at,
        engine_count: 1,
        selected_engines: [{ id: "backend.llama-cpp", selected: true }],
        selected_engine_ids: ["backend.llama-cpp"],
        runtime_preference: { selected_engine_id: "backend.llama-cpp" },
        hardware: {
          status: "checked",
          cpu_count: 8,
          total_memory_bytes: 1024,
          js_probe_execution: false,
        },
        lm_studio: { status: "not_checked", js_cli_execution: false },
        runtime_survey_hash: "sha256:runtime-survey",
        rust_core_boundary: "model_mount.runtime_survey",
        operation_kind: request.operation_kind,
        rust_daemon_core_receipt_author: "model_mount.runtime_survey",
        js_hardware_probe_executed: false,
        js_runtime_engine_read_executed: false,
        js_lm_studio_probe_executed: false,
        agentgres_receipt_state_commit_required: true,
      },
    },
    receipt_refs: ["receipt_runtime_survey_test"],
    evidence_refs: [
      "model_mount_runtime_survey_js_facade_retired",
      "rust_daemon_core_runtime_survey",
      "agentgres_runtime_survey_truth_required",
      "rust_model_mount_core",
    ],
    survey_hash: "sha256:runtime-survey",
    operation_kind: request.operation_kind,
    rust_core_boundary: "model_mount.runtime_survey",
  };
}

function fakeState({ withRunner = true } = {}) {
  const state = {
    stateDir: "/runtime-state",
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
      void kind;
      void payload;
      throw new Error("JS receipt creation must stay retired for runtime survey");
    },
    store: {
      commits: [],
      writeReceipt(receipt) {
        this.commits.push(receipt);
        return {
          source: "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
          receipt_id: receipt.id,
          object_ref:
            `agentgres://model-mounting/receipts/${receipt.id}/records/receipts/${receipt.id}.json`,
          content_hash: "sha256:receipt-content",
          admission_hash: "sha256:receipt-admission",
          commit_hash: "sha256:receipt-commit",
          written_record: { record_path: `receipts/${receipt.id}.json` },
        };
      },
    },
    writeProjection() {
      throw new Error("JS projection writes must stay retired for runtime survey");
    },
  };
  if (withRunner) {
    state.runtimeSurveyRequests = [];
    state.modelMountAdmissionRunner = {
      planRuntimeSurvey(request) {
        state.runtimeSurveyRequests.push(request);
        return runtimeSurveyPlan(request);
      },
    };
  }
  return state;
}

test("runtimeSurvey commits Rust-authored receipt before returning public survey", () => {
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

  const survey = ModelMountingState.prototype.runtimeSurvey.call(state);

  assert.equal(hardwareCalls, 0);
  assert.equal(engineCalls, 0);
  assert.equal(lmStudioCalls, 0);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.runtimeSurveyRequests.length, 1);
  assert.equal(state.runtimeSurveyRequests[0].schema_version, "ioi.model_mount.runtime_survey.v1");
  assert.equal(state.runtimeSurveyRequests[0].operation_kind, "model_mount.runtime_survey.capture");
  assert.equal(state.runtimeSurveyRequests[0].source, "runtime-daemon.model_mounting.runtime_survey");
  assert.equal(state.runtimeSurveyRequests[0].generated_at, "2026-06-03T12:00:00.000Z");
  assert.equal(state.runtimeSurveyRequests[0].state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(state.runtimeSurveyRequests[0], "hardware"), false);
  assert.equal(Object.hasOwn(state.runtimeSurveyRequests[0], "engines"), false);
  assert.equal(Object.hasOwn(state.runtimeSurveyRequests[0], "lmStudio"), false);
  assert.equal(state.store.commits.length, 1);
  assert.equal(state.store.commits[0].kind, "runtime_survey");
  assert.equal(state.store.commits[0].details.engine_count, 1);
  assert.equal(Object.hasOwn(state.store.commits[0].details, "engineCount"), false);
  assert.equal(Object.hasOwn(state.store.commits[0].details, "runtimePreference"), false);
  assert.equal(state.store.commits[0].details.js_hardware_probe_executed, false);
  assert.equal(survey.status, "checked");
  assert.equal(survey.receiptId, "receipt_runtime_survey_test");
  assert.equal(survey.receiptCommitHash, "sha256:receipt-commit");
  assert.equal(survey.receiptStateCommit.admissionHash, "sha256:receipt-admission");
  assert.deepEqual(survey.selectedEngineIds, ["backend.llama-cpp"]);
  assert.equal(survey.hardware.jsProbeExecution, false);
  assert.equal(survey.jsRuntimeEngineReadExecuted, false);
});

test("runtimeSurvey fails closed before JS probes when Rust planner is missing", () => {
  const state = fakeState({ withRunner: false });
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
      assert.equal(error.details.missing, "modelMountAdmissionRunner.planRuntimeSurvey");
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
  assert.equal(state.store.commits.length, 0);
});
