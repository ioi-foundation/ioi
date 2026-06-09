export function runtimeSurvey(state, deps = {}) {
  void state;
  void deps;
  throwRuntimeSurveyRustCoreRequired({
    operation: "runtime_survey",
    operation_kind: "model_mount.runtime_survey.capture",
  });
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
