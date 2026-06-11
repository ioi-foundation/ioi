import { optionalString } from "./runtime-value-helpers.mjs";

const EVIDENCE_REFS = [
  "runtime_lifecycle_js_projection_retired",
  "rust_daemon_core_runtime_lifecycle_projection_required",
  "agentgres_runtime_lifecycle_truth_required",
];

export function createRuntimeLifecycleProjectionSurface({
  lifecycleRunner = null,
  workspaceRoot = null,
} = {}) {
  const fail = (projection) =>
    throwRuntimeLifecycleProjectionRustCoreRequired({
      lifecycleRunner,
      workspace_root: workspaceRoot,
      ...projection,
    });

  return {
    listAgents() {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.agents",
        projection_kind: "agents",
      });
    },
    getAgent(_store, agentId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.agent",
        projection_kind: "agent",
        agent_id: optionalString(agentId),
      });
    },
    listThreads() {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.threads",
        projection_kind: "threads",
      });
    },
    getThread(_store, threadId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.thread",
        projection_kind: "thread",
        thread_id: optionalString(threadId),
      });
    },
    listRuns(_store, agentId = null) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: agentId
          ? "runtime.lifecycle_projection.agent_runs"
          : "runtime.lifecycle_projection.runs",
        projection_kind: agentId ? "agent_runs" : "runs",
        agent_id: optionalString(agentId),
      });
    },
    getRun(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run",
        projection_kind: "run",
        run_id: optionalString(runId),
      });
    },
    waitRun(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_wait",
        projection_kind: "run_wait",
        run_id: optionalString(runId),
      });
    },
    getRunConversation(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_conversation",
        projection_kind: "run_conversation",
        run_id: optionalString(runId),
      });
    },
    getRunTrace(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_trace",
        projection_kind: "run_trace",
        run_id: optionalString(runId),
      });
    },
    getRunComputerUseTrace(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_computer_use_trace",
        projection_kind: "run_computer_use_trace",
        run_id: optionalString(runId),
      });
    },
    getRunComputerUseTrajectory(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_computer_use_trajectory",
        projection_kind: "run_computer_use_trajectory",
        run_id: optionalString(runId),
      });
    },
    getRunScorecard(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_scorecard",
        projection_kind: "run_scorecard",
        run_id: optionalString(runId),
      });
    },
    listRunArtifacts(_store, runId) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_artifacts",
        projection_kind: "run_artifacts",
        run_id: optionalString(runId),
      });
    },
    getRunArtifact(_store, runId, artifactRef) {
      fail({
        operation: "runtime_lifecycle_projection",
        operation_kind: "runtime.lifecycle_projection.run_artifact",
        projection_kind: "run_artifact",
        run_id: optionalString(runId),
        artifact_ref: optionalString(artifactRef),
      });
    },
  };
}

function throwRuntimeLifecycleProjectionRustCoreRequired(details = {}) {
  const { lifecycleRunner = null, ...errorDetails } = details;
  if (lifecycleRunner?.planRuntimeLifecycleProjectionRequired) {
    const record = lifecycleRunner.planRuntimeLifecycleProjectionRequired({
      ...errorDetails,
      source: "runtime.lifecycle_projection_surface",
      evidence_refs: EVIDENCE_REFS,
    });
    const planned = record?.record ?? record;
    throw createRuntimeLifecycleProjectionError(planned ?? record, {
      ...errorDetails,
      source: "runtime.lifecycle_projection_surface",
      evidence_refs: EVIDENCE_REFS,
    });
  }

  throw createRuntimeLifecycleProjectionError(null, {
    ...errorDetails,
    source: "runtime.lifecycle_projection_surface",
    evidence_refs: EVIDENCE_REFS,
  });
}

function createRuntimeLifecycleProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Runtime agent, thread, and run lifecycle projections require direct Rust daemon-core projection over Agentgres-admitted lifecycle truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_lifecycle_projection_rust_core_required";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.lifecycle_projection",
    ...fallbackDetails,
  };
  return error;
}
