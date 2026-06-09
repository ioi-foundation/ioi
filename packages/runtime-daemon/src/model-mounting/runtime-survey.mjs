export function runtimeSurvey(state, deps = {}) {
  throwRuntimeSurveyRustCoreRequired({
    operation: "runtime_survey",
    operation_kind: "model_mount.runtime_survey.capture",
  });
}

export function latestRuntimeSurveyProjectionInput(state, deps = {}) {
  const { hardwareSnapshot } = deps;
  return {
    engine_count: state.listRuntimeEngines().length,
    runtime_preference: state.runtimePreference(),
    hardware: hardwareSnapshot(),
  };
}

export function lmStudioRuntimeEngines(state, checkedAt, deps = {}) {
  return [];
}

export function lmStudioRuntimeSurvey(state, checkedAt, deps = {}) {
  return {
    status: "not_checked",
    checkedAt,
    rustCoreBoundary: "model_mount.runtime_survey",
    evidenceRefs: [
      "lm_studio_public_runtime_survey_retired",
      "rust_daemon_core_runtime_survey_required",
      "agentgres_runtime_survey_projection_required",
    ],
  };
}

function throwRuntimeSurveyRustCoreRequired(details = {}) {
  const error = new Error("Runtime survey capture requires direct Rust daemon-core model_mount projection support.");
  error.status = 501;
  error.code = "model_mount_runtime_survey_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.runtime_survey",
    ...details,
    evidence_refs: [
      "model_mount_runtime_survey_js_facade_retired",
      "rust_daemon_core_runtime_survey_required",
      "agentgres_runtime_survey_projection_required",
    ],
  };
  throw error;
}
