import { relative } from "node:path";

import {
  getRun as getRunState,
  listRuns as listRunsState,
  usageForRun as usageForRunState,
  usageForThread as usageForThreadState,
} from "./threads/thread-store.mjs";
import {
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
} from "./usage-telemetry.mjs";
import { threadIdForAgent } from "./runtime-identifiers.mjs";

function defaultRuntimeJobRecordForRun(run = {}) {
  return { jobId: run.id };
}

function defaultRuntimeChecklistRecordForRun(run = {}) {
  return { checklistId: run.id };
}

function runStateProjectionWatermark(store) {
  return store.runs instanceof Map ? store.runs.size : 0;
}

export function createRuntimeRunReadSurface({
  getRun: getRunDep = getRunState,
  listRuns: listRunsDep = listRunsState,
  relative: relativeDep = relative,
  runtimeChecklistRecordForRun,
  runtimeJobRecordForRun,
  runtimeUsageTelemetryForRun: runtimeUsageTelemetryForRunDep = runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread: runtimeUsageTelemetryForThreadDep = runtimeUsageTelemetryForThread,
  threadIdForAgent: threadIdForAgentDep = threadIdForAgent,
  usageForRun: usageForRunDep = usageForRunState,
  usageForThread: usageForThreadDep = usageForThreadState,
  notFound,
} = {}) {
  const runtimeJobRecordForRunDep =
    runtimeJobRecordForRun ?? defaultRuntimeJobRecordForRun;
  const runtimeChecklistRecordForRunDep =
    runtimeChecklistRecordForRun ?? defaultRuntimeChecklistRecordForRun;

  return {
    getRun(store, runId) {
      return getRunDep(store, runId, { notFound });
    },
    listRuns(store, agentId) {
      return listRunsDep(store, agentId);
    },
    usageForRun(store, runId) {
      return usageForRunDep(store, runId, {
        runtimeUsageTelemetryForRun: runtimeUsageTelemetryForRunDep,
        threadIdForAgent: threadIdForAgentDep,
      });
    },
    usageForThread(store, threadId) {
      return usageForThreadDep(store, threadId, {
        runtimeUsageTelemetryForThread: runtimeUsageTelemetryForThreadDep,
      });
    },
    traceFromCanonicalState(store, runId) {
      return store.getRun(runId).trace;
    },
    canonicalProjection(store, runId) {
      const run = store.getRun(runId);
      const watermark = runStateProjectionWatermark(store);
      return {
        schemaVersion: store.schemaVersion,
        runId,
        source: "agentgres_canonical_state_projection",
        watermark,
        freshness: {
          source: "local-agentgres-v0",
          runStateWatermark: watermark,
          generatedAt: new Date().toISOString(),
        },
        paths: {
          run: relativeDep(store.stateDir, store.pathFor("runs", `${run.id}.json`)),
          task: relativeDep(store.stateDir, store.pathFor("tasks", `${run.id}.json`)),
          job: relativeDep(store.stateDir, store.pathFor("jobs", `${runtimeJobRecordForRunDep(run).jobId}.json`)),
          checklist: relativeDep(store.stateDir, store.pathFor("checklists", `${runtimeChecklistRecordForRunDep(run).checklistId}.json`)),
          quality: relativeDep(store.stateDir, store.pathFor("quality", `${run.id}.json`)),
        },
        terminalState: run.status,
        stopCondition: run.trace.stopCondition,
        scorecard: run.trace.scorecard,
      };
    },
  };
}
