import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const EVIDENCE_REFS = [
  "runtime_lifecycle_rust_projection",
  "agentgres_runtime_lifecycle_truth_required",
];

const ARRAY_PROJECTION_KINDS = new Set([
  "agents",
  "threads",
  "thread_turns",
  "thread_events",
  "runs",
  "agent_runs",
  "run_conversation",
  "run_events",
  "run_replay",
  "run_computer_use_trajectory",
  "run_artifacts",
]);

const LIFECYCLE_PROJECTIONS = {
  agents: projection("agents"),
  agent: projection("agent"),
  threads: projection("threads"),
  thread: projection("thread"),
  thread_usage: projection("thread_usage"),
  thread_turns: projection("thread_turns"),
  thread_turn: projection("thread_turn"),
  thread_events: projection("thread_events"),
  runs: projection("runs"),
  agent_runs: projection("agent_runs"),
  run: projection("run"),
  run_wait: projection("run_wait"),
  run_conversation: projection("run_conversation"),
  run_usage: projection("run_usage"),
  run_events: projection("run_events"),
  run_replay: projection("run_replay"),
  run_trace: projection("run_trace"),
  run_computer_use_trace: projection("run_computer_use_trace"),
  run_computer_use_trajectory: projection("run_computer_use_trajectory"),
  run_scorecard: projection("run_scorecard"),
  run_artifacts: projection("run_artifacts"),
  run_artifact: projection("run_artifact"),
  usage_list: projection("usage_list"),
  authority_evidence_summary: projection("authority_evidence_summary"),
};

export function createRuntimeLifecycleProjectionSurface({
  contextPolicyCore = null,
  workspaceRoot = null,
} = {}) {
  const project = (store, projectionDetails, facts = {}) =>
    projectRuntimeLifecycle({
      contextPolicyCore,
      workspace_root: workspaceRoot ?? store?.defaultCwd,
      state_dir: lifecycleProjectionStateDir(store),
      ...projectionDetails,
      ...facts,
    });

  return {
    listAgents(store) {
      return project(store, LIFECYCLE_PROJECTIONS.agents);
    },
    getAgent(store, agentId) {
      return project(store, LIFECYCLE_PROJECTIONS.agent, {
        agent_id: optionalString(agentId),
      });
    },
    listThreads(store) {
      return project(store, LIFECYCLE_PROJECTIONS.threads);
    },
    getThread(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread, {
        thread_id: optionalString(threadId),
      });
    },
    getThreadUsage(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_usage, {
        thread_id: optionalString(threadId),
      });
    },
    listThreadTurns(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_turns, {
        thread_id: optionalString(threadId),
      });
    },
    getThreadTurn(store, threadId, turnId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_turn, {
        thread_id: optionalString(threadId),
        turn_id: optionalString(turnId),
      });
    },
    listThreadEvents(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_events, {
        thread_id: optionalString(threadId),
      });
    },
    listRuns(store, agentId = null) {
      const canonicalAgentId = optionalString(agentId);
      return project(
        store,
        canonicalAgentId
          ? LIFECYCLE_PROJECTIONS.agent_runs
          : LIFECYCLE_PROJECTIONS.runs,
        {
          agent_id: canonicalAgentId,
        },
      );
    },
    getRun(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run, {
        run_id: optionalString(runId),
      });
    },
    waitRun(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_wait, {
        run_id: optionalString(runId),
      });
    },
    getRunConversation(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_conversation, {
        run_id: optionalString(runId),
      });
    },
    getRunUsage(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_usage, {
        run_id: optionalString(runId),
      });
    },
    listRunEvents(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_events, {
        run_id: optionalString(runId),
      });
    },
    replayRun(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_replay, {
        run_id: optionalString(runId),
      });
    },
    getRunTrace(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_trace, {
        run_id: optionalString(runId),
      });
    },
    getRunComputerUseTrace(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_computer_use_trace, {
        run_id: optionalString(runId),
      });
    },
    getRunComputerUseTrajectory(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_computer_use_trajectory, {
        run_id: optionalString(runId),
      });
    },
    getRunScorecard(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_scorecard, {
        run_id: optionalString(runId),
      });
    },
    listRunArtifacts(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_artifacts, {
        run_id: optionalString(runId),
      });
    },
    getRunArtifact(store, runId, artifactRef) {
      return project(store, LIFECYCLE_PROJECTIONS.run_artifact, {
        run_id: optionalString(runId),
        artifact_ref: optionalString(artifactRef),
      });
    },
    listUsage(store, options = {}) {
      return project(store, LIFECYCLE_PROJECTIONS.usage_list, {
        agent_id: optionalString(options.agent_id),
        group_by: optionalString(options.group_by),
      });
    },
    authorityEvidenceSummary(store, options = {}) {
      return project(store, LIFECYCLE_PROJECTIONS.authority_evidence_summary, {
        thread_id: optionalString(options.thread_id),
        run_id: optionalString(options.run_id),
        capability_ref: optionalString(options.capability_ref),
        route_id: optionalString(options.route_id),
      });
    },
  };
}

function projection(projectionKind) {
  return {
    operation: "runtime_lifecycle_projection",
    operation_kind: `runtime.lifecycle_projection.${projectionKind}`,
    projection_kind: projectionKind,
  };
}

function projectRuntimeLifecycle(details = {}) {
  const { contextPolicyCore = null, ...request } = details;
  if (!contextPolicyCore?.projectRuntimeLifecycle) {
    throw createRuntimeLifecycleProjectionError(null, {
      ...request,
      source: "runtime.lifecycle_projection_surface",
      evidence_refs: EVIDENCE_REFS,
    });
  }

  const result = contextPolicyCore.projectRuntimeLifecycle({
    ...request,
    source: "runtime.lifecycle_projection_surface",
    evidence_refs: EVIDENCE_REFS,
  });
  if (result?.projection_kind !== request.projection_kind) {
    throw createRuntimeLifecycleProjectionMismatchError(result, request);
  }
  if (ARRAY_PROJECTION_KINDS.has(request.projection_kind)) {
    if (Array.isArray(result?.projection)) return result.projection;
    throw createRuntimeLifecycleProjectionMismatchError(result, request);
  }
  if (objectRecord(result?.projection) || result?.projection === null) {
    return result.projection;
  }
  throw createRuntimeLifecycleProjectionMismatchError(result, request);
}

function lifecycleProjectionStateDir(store) {
  return optionalString(store?.stateDir) ?? null;
}

function createRuntimeLifecycleProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Runtime agent, thread, and run lifecycle projections require Rust daemon-core projection over Agentgres-admitted lifecycle truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_lifecycle_projection_rust_projection_missing";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.lifecycle_projection",
    ...fallbackDetails,
  };
  return error;
}

function createRuntimeLifecycleProjectionMismatchError(result, fallbackDetails) {
  const error = new Error(
    "Rust runtime lifecycle projection returned an invalid route projection.",
  );
  error.status = 502;
  error.code = "runtime_lifecycle_projection_rust_projection_invalid";
  error.details = {
    rust_core_boundary: "runtime.lifecycle_projection",
    expected_projection_kind: fallbackDetails.projection_kind,
    actual_projection_kind: result?.projection_kind ?? null,
    operation: fallbackDetails.operation,
    operation_kind: fallbackDetails.operation_kind,
    source: "runtime.lifecycle_projection_surface",
  };
  return error;
}
