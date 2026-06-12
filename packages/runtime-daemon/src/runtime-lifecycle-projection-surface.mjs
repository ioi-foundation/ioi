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
};

export function createRuntimeLifecycleProjectionSurface({
  lifecycleRunner = null,
  workspaceRoot = null,
  resolveRunArtifact = defaultResolveRunArtifact,
} = {}) {
  const project = (store, projectionDetails, facts = {}) =>
    projectRuntimeLifecycle({
      lifecycleRunner,
      workspace_root: workspaceRoot ?? store?.defaultCwd,
      ...projectionDetails,
      ...facts,
    });

  return {
    listAgents(store) {
      return project(store, LIFECYCLE_PROJECTIONS.agents, {
        agents: agentRecords(store),
      });
    },
    getAgent(store, agentId) {
      return project(store, LIFECYCLE_PROJECTIONS.agent, {
        agent_id: optionalString(agentId),
        agents: agentRecords(store),
        agent: agentRecord(store, agentId),
      });
    },
    listThreads(store) {
      return project(store, LIFECYCLE_PROJECTIONS.threads, {
        agents: agentRecords(store),
        threads: threadRecords(store),
      });
    },
    getThread(store, threadId) {
      const threads = threadRecords(store);
      return project(store, LIFECYCLE_PROJECTIONS.thread, {
        thread_id: optionalString(threadId),
        agents: agentRecords(store),
        threads,
        thread: threads.find((thread) => thread?.thread_id === threadId || thread?.id === threadId) ?? null,
      });
    },
    getThreadUsage(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_usage, {
        thread_id: optionalString(threadId),
        usage: callStore(store, "usageForThread", threadId),
      });
    },
    listThreadTurns(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_turns, {
        thread_id: optionalString(threadId),
        turns: callStore(store, "listTurns", threadId, []),
      });
    },
    getThreadTurn(store, threadId, turnId) {
      const turns = callStore(store, "listTurns", threadId, []);
      return project(store, LIFECYCLE_PROJECTIONS.thread_turn, {
        thread_id: optionalString(threadId),
        turn_id: optionalString(turnId),
        turns,
        turn:
          turns.find((turn) => turn?.turn_id === turnId || turn?.id === turnId) ??
          null,
      });
    },
    listThreadEvents(store, threadId) {
      return project(store, LIFECYCLE_PROJECTIONS.thread_events, {
        thread_id: optionalString(threadId),
        events: callStore(store, "eventsForThread", threadId, []),
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
          agents: agentRecords(store),
          runs: runRecords(store),
        },
      );
    },
    getRun(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run, {
        run_id: optionalString(runId),
        agents: agentRecords(store),
        runs: runRecords(store),
        run,
      });
    },
    waitRun(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_wait, {
        run_id: optionalString(runId),
        runs: runRecords(store),
        run,
      });
    },
    getRunConversation(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_conversation, {
        run_id: optionalString(runId),
        run,
        conversation: Array.isArray(run?.conversation) ? run.conversation : [],
      });
    },
    getRunUsage(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_usage, {
        run_id: optionalString(runId),
        usage: callStore(store, "usageForRun", runId),
      });
    },
    listRunEvents(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_events, {
        run_id: optionalString(runId),
        events: callStore(store, "eventsForRun", runId, []),
      });
    },
    replayRun(store, runId) {
      return project(store, LIFECYCLE_PROJECTIONS.run_replay, {
        run_id: optionalString(runId),
        replay: callStore(store, "replayFromCanonicalState", runId, []),
      });
    },
    getRunTrace(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_trace, {
        run_id: optionalString(runId),
        run,
        trace: run?.trace ?? null,
      });
    },
    getRunComputerUseTrace(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_computer_use_trace, {
        run_id: optionalString(runId),
        run,
        trace: run?.trace ?? null,
        computer_use_trace:
          run?.trace?.computerUse?.trace ??
          run?.trace?.computer_use?.trace ??
          run?.trace?.computer_use_trace ??
          null,
      });
    },
    getRunComputerUseTrajectory(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_computer_use_trajectory, {
        run_id: optionalString(runId),
        run,
        trace: run?.trace ?? null,
        computer_use_trajectory:
          run?.trace?.computerUse?.trajectory ??
          run?.trace?.computer_use?.trajectory ??
          run?.trace?.computer_use_trajectory ??
          null,
      });
    },
    getRunScorecard(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_scorecard, {
        run_id: optionalString(runId),
        run,
        trace: run?.trace ?? null,
        scorecard: run?.trace?.scorecard ?? null,
      });
    },
    listRunArtifacts(store, runId) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_artifacts, {
        run_id: optionalString(runId),
        run,
        artifacts: Array.isArray(run?.artifacts) ? run.artifacts : [],
      });
    },
    getRunArtifact(store, runId, artifactRef) {
      const run = runRecord(store, runId);
      return project(store, LIFECYCLE_PROJECTIONS.run_artifact, {
        run_id: optionalString(runId),
        artifact_ref: optionalString(artifactRef),
        run,
        artifacts: Array.isArray(run?.artifacts) ? run.artifacts : [],
        artifact: resolveRunArtifact(run ?? {}, artifactRef),
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
  const { lifecycleRunner = null, ...request } = details;
  if (!lifecycleRunner?.projectRuntimeLifecycle) {
    throw createRuntimeLifecycleProjectionError(null, {
      ...request,
      source: "runtime.lifecycle_projection_surface",
      evidence_refs: EVIDENCE_REFS,
    });
  }

  const result = lifecycleRunner.projectRuntimeLifecycle({
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

function agentRecords(store) {
  if (store?.agents instanceof Map) return [...store.agents.values()];
  return Array.isArray(store?.agents) ? store.agents : [];
}

function agentRecord(store, agentId) {
  const id = optionalString(agentId);
  if (!id) return null;
  if (store?.agents instanceof Map) return store.agents.get(id) ?? null;
  return agentRecords(store).find((agent) => agent?.id === id || agent?.agent_id === id) ?? null;
}

function threadRecords(store) {
  if (typeof store?.listThreads !== "function") return [];
  const result = store.listThreads();
  return Array.isArray(result) ? result : [];
}

function runRecords(store) {
  if (store?.runs instanceof Map) return [...store.runs.values()];
  return Array.isArray(store?.runs) ? store.runs : [];
}

function runRecord(store, runId) {
  const id = optionalString(runId);
  if (!id) return null;
  if (store?.runs instanceof Map) return store.runs.get(id) ?? null;
  return runRecords(store).find((run) => run?.id === id || run?.run_id === id) ?? null;
}

function callStore(store, method, firstArg, fallback = null) {
  if (typeof store?.[method] !== "function") return fallback;
  const result = store[method](firstArg);
  return result ?? fallback;
}

function defaultResolveRunArtifact(run = {}, artifactRef) {
  const ref = optionalString(artifactRef);
  if (!ref || !Array.isArray(run?.artifacts)) return null;
  return (
    run.artifacts.find(
      (artifact) =>
        artifact?.id === ref ||
        artifact?.name === ref ||
        artifact?.artifactRef === ref ||
        artifact?.artifact_ref === ref,
    ) ?? null
  );
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
