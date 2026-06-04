import { relative } from "node:path";

import {
  getRun as getRunState,
  listRuns as listRunsState,
  usageForRun as usageForRunState,
  usageForThread as usageForThreadState,
} from "./threads/thread-store.mjs";
import { authorityEvidenceSummaryForEvents } from "./authority-evidence-summary.mjs";
import {
  runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread,
  runtimeUsageTelemetryList,
} from "./usage-telemetry.mjs";
import { threadIdForAgent } from "./runtime-identifiers.mjs";

function defaultRuntimeJobRecordForRun(run = {}) {
  return { jobId: run.runtimeJob?.jobId ?? run.jobId ?? run.id };
}

function defaultRuntimeChecklistRecordForRun(run = {}) {
  return { checklistId: run.runtimeChecklist?.checklistId ?? run.checklistId ?? run.id };
}

export function createRuntimeRunReadSurface({
  authorityEvidenceSummaryForEvents: authorityEvidenceSummaryForEventsDep = authorityEvidenceSummaryForEvents,
  getRun: getRunDep = getRunState,
  listRuns: listRunsDep = listRunsState,
  relative: relativeDep = relative,
  runtimeChecklistRecordForRun,
  runtimeJobRecordForRun,
  runtimeUsageTelemetryForRun: runtimeUsageTelemetryForRunDep = runtimeUsageTelemetryForRun,
  runtimeUsageTelemetryForThread: runtimeUsageTelemetryForThreadDep = runtimeUsageTelemetryForThread,
  runtimeUsageTelemetryList: runtimeUsageTelemetryListDep = runtimeUsageTelemetryList,
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
    listUsage(store, options = {}) {
      const groupBy = options.group_by ?? options.groupBy ?? "run";
      const agentId = options.agentId ?? options.agent_id;
      const parentThreadId = agentId ? threadIdForAgentDep(agentId) : null;
      return runtimeUsageTelemetryListDep({
        runs: store.listRuns(agentId),
        subagents: [...store.subagents.values()].filter(
          (record) =>
            !parentThreadId || (record.parent_thread_id ?? record.parentThreadId) === parentThreadId,
        ),
        groupBy,
      });
    },
    authorityEvidenceSummary(store, options = {}) {
      for (const agent of store.agents.values()) {
        store.projectThreadEvents(agent);
      }
      return authorityEvidenceSummaryForEventsDep(
        [...store.runtimeEventStreams.values()].flatMap((stream) => stream.events),
        options,
      );
    },
    legacyEventsForRun(store, runId, lastEventId) {
      const events = store.getRun(runId).events;
      if (!lastEventId) return events;
      const index = events.findIndex((event) => event.id === lastEventId);
      return events.slice(index >= 0 ? index + 1 : 0);
    },
    replayFromCanonicalState(store, runId, cursor) {
      return store.eventsForRun(runId, cursor);
    },
    traceFromCanonicalState(store, runId) {
      return store.getRun(runId).trace;
    },
    canonicalProjection(store, runId) {
      const run = store.getRun(runId);
      const watermark = store.operationCount();
      return {
        schemaVersion: store.schemaVersion,
        runId,
        source: "agentgres_canonical_operation_log",
        watermark,
        freshness: {
          source: "local-agentgres-v0",
          operationCount: watermark,
          generatedAt: new Date().toISOString(),
        },
        paths: {
          run: relativeDep(store.stateDir, store.pathFor("runs", `${run.id}.json`)),
          task: relativeDep(store.stateDir, store.pathFor("tasks", `${run.id}.json`)),
          job: relativeDep(store.stateDir, store.pathFor("jobs", `${runtimeJobRecordForRunDep(run).jobId}.json`)),
          checklist: relativeDep(store.stateDir, store.pathFor("checklists", `${runtimeChecklistRecordForRunDep(run).checklistId}.json`)),
          quality: relativeDep(store.stateDir, store.pathFor("quality", `${run.id}.json`)),
          operationLog: "operation-log.jsonl",
        },
        terminalState: run.status,
        stopCondition: run.trace.stopCondition,
        scorecard: run.trace.scorecard,
      };
    },
  };
}
