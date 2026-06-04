import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioStage7DelegationLifecycle } = require("./stage7-delegation-lifecycle.js");

test("stage7 delegation lifecycle preserves parent child recovery proof envelope", async () => {
  const bridgeRequests = [];
  const receipts = [];
  const timeline = [];
  const appliedEvents = [];
  const refreshes = [];
  let replayRefreshed = false;
  let cockpitRecomputed = false;
  let subagentListReads = 0;
  const requests = [];
  const projection = {
    modelRoute: "route.local-first",
    selectedModel: "auto",
    workerCards: [],
    browserCards: [],
    workerContributionTraces: [],
    trajectoryReplayPanels: [],
    runtimeCockpit: {},
  };
  const failedChild = {
    subagent_id: "subagent-failed",
    role: "failed-child",
    status: "blocked",
    block_reason: "subagent_budget_exceeded",
    receipt_refs: ["receipt_failed_child_source"],
  };
  const recoveredFailedChild = {
    ...failedChild,
    status: "completed",
    restart_status: "restarted",
    receipt_refs: ["receipt_stage7_failed_child_recovered"],
  };
  const worker = {
    subagent_id: "subagent-worker",
    role: "repo-verifier",
    status: "completed",
    receipt_refs: ["receipt_stage7_delegated_worker_source"],
  };
  const browser = {
    subagent_id: "subagent-browser",
    role: "browser",
    status: "completed",
    receipt_refs: ["receipt_stage7_browser_subagent_managed_artifact"],
  };

  const lifecycle = createStudioStage7DelegationLifecycle({
    appendStudioReceiptsFromResponse: (response, kind, detail) => receipts.push({ response, kind, detail }),
    appendStudioTimeline: (...args) => timeline.push(args),
    applyStudioAgentTurnEvents: (events, options) => appliedEvents.push({ events, options }),
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    fetchStudioThreadEvents: async () => [{ kind: "subagent.completed", receipt_refs: ["receipt-event"] }],
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => projection,
    isAutoStudioModelSelector: (value) => value === "auto",
    normalizeReceiptRefs: (record = {}) => {
      const refs = record.receipt_refs || record.receiptRefs || [];
      return Array.isArray(refs) ? refs : [];
    },
    recomputeStudioRuntimeCockpitAchieved: () => {
      cockpitRecomputed = true;
    },
    refreshStudioPanelHtml: async (output) => refreshes.push(output),
    refreshStudioReplayStepsFromProjection: () => {
      replayRefreshed = true;
    },
    requestJson: async (endpoint, route, options = {}) => {
      requests.push({ endpoint, route, options });
      if (route === "/v1/threads" && options.method === "POST") {
        return {
          thread_id: "thread-stage7",
          session_id: "session-stage7",
          model_route_id: "route.local-first",
          selected_model: "auto",
        };
      }
      if (route.endsWith("/turns") && options.method === "POST") {
        return { turn_id: "turn-parent", run_id: "run-parent", receipt_refs: ["receipt_parent"] };
      }
      if (route.endsWith("/subagents") && options.method === "POST") {
        if (options.payload.role === "repo-verifier") return worker;
        if (options.payload.role === "failed-child") {
          throw new Error("subagent budget exceeded");
        }
        if (options.payload.role === "browser") return browser;
      }
      if (route.endsWith("/resume") && options.method === "POST") {
        return recoveredFailedChild;
      }
      if (route.endsWith("/subagents")) {
        subagentListReads += 1;
        if (subagentListReads === 1) return { subagents: [worker, failedChild] };
        return { subagents: [worker, recoveredFailedChild, browser] };
      }
      throw new Error(`unexpected route ${route}`);
    },
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    uniqueStrings: (values = []) => [...new Set(values.filter(Boolean))],
    workspaceSummary: () => ({ path: "/workspace/repo" }),
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const result = await lifecycle.exerciseStudioStage7DelegationLifecycle({ appendLine() {} });

  assert.equal(result.passed, true);
  assert.equal(result.threadId, "thread-stage7");
  assert.equal(result.parentTurnId, "turn-parent");
  assert.equal(result.subagentCount, 3);
  assert.deepEqual(result.workerIds, ["subagent-worker", "subagent-failed", "subagent-browser"]);
  assert.equal(projection.threadId, "thread-stage7");
  assert.equal(projection.sessionId, "session-stage7");
  assert.equal(projection.executionMode, "agent");
  assert.equal(projection.runtimeProfile, "fixture");
  assert.equal(projection.status, "active");
  assert.equal(projection.workerCards.length, 1);
  assert.match(projection.workerCards[0].detail, /delegated worker, recovered failed child, and browser subagent/);
  assert.equal(projection.browserCards[0].status, "completed");
  assert.equal(projection.workerContributionTraces[0].contributionCount, 3);
  assert.equal(projection.trajectoryReplayPanels[0].rows[1].summary, "failed child recovered");
  assert.equal(projection.runtimeCockpit.workerStatusObserved, true);
  assert.equal(projection.runtimeCockpit.browserStatusObserved, true);
  assert.equal(replayRefreshed, true);
  assert.equal(cockpitRecomputed, true);
  assert.equal(refreshes.length, 1);
  assert.equal(appliedEvents[0].options.projectAnswerStream, false);
  assert.deepEqual(receipts.map((record) => record.kind), [
    "stage7_parent_turn",
    "stage7_delegated_worker",
    "stage7_failed_child_recovery",
    "stage7_browser_subagent",
  ]);
  assert.equal(bridgeRequests[0][0], "studio.stage7DelegationLifecycle.exercised");
  assert.equal(bridgeRequests[0][1].sourceCommand, "ioi.studio.exerciseStage7DelegationLifecycle");
  assert.equal(bridgeRequests[0][1].runtimeAuthority, "daemon-owned");
  assert.equal(bridgeRequests[0][1].ownsRuntimeState, false);
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.equal(bridgeRequests[0][1].checks.failedChildRecovered, true);
  assert.deepEqual(bridgeRequests[0][1].subagentIds, {
    delegatedWorker: "subagent-worker",
    failedChild: "subagent-failed",
    browserSubagent: "subagent-browser",
  });
  assert.equal(bridgeRequests[0][2].source, "studio-stage7-delegation");
  assert.equal(requests[0].options.payload.options.local.cwd, "/workspace/repo");
});
