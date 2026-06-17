import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const {
  STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
  createStudioDurabilityPanels,
} = require("./durability-panels.js");

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function stringValue(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function uniqueStrings(values = []) {
  return [...new Set(firstArray(values).filter((value) => typeof value === "string" && value.length > 0))];
}

function normalizeReceiptRefs(...sources) {
  const refs = [];
  for (const source of sources) {
    if (!source) continue;
    if (typeof source === "string") {
      refs.push(source);
      continue;
    }
    refs.push(
      ...firstArray(source.receipt_refs),
      ...firstArray(source.receiptRefs),
      ...firstArray(source.receipts).map((receipt) => receipt?.id || receipt?.receipt_id || receipt?.receiptId),
      ...firstArray(source.payload_summary?.receipt_refs),
      ...firstArray(source.payload_summary?.receiptRefs),
    );
  }
  return uniqueStrings(refs);
}

function panels() {
  return createStudioDurabilityPanels({
    firstArray,
    normalizeReceiptRefs,
    stringValue,
    studioRuntimeEventKind: (event = {}) => stringValue(event.kind || event.type, "runtime.event"),
    uniqueStrings,
    workspacePath: () => "/workspace/project",
  });
}

test("session brain projection verifies required artifacts, receipts, and workspace boundary", () => {
  const projection = panels();
  const panel = projection.studioSessionBrainPanelFromProjection({
    memoryProjection: {
      workspace: "/workspace/project",
      policy: { read_only: true },
      records: [
        {
          id: "record-plan",
          memoryKey: "implementation_plan",
          text: "Plan text",
          receiptRefs: ["receipt-plan"],
        },
        {
          id: "record-task",
          memory_key: "task",
          fact: "Task checklist",
          evidenceRefs: ["task.md"],
        },
        {
          id: "record-walkthrough",
          memoryKey: "walkthrough",
          text: "Walkthrough",
        },
        {
          id: "record-scratch",
          memoryKey: "scratch/eval",
          text: "Scratch note",
        },
      ],
    },
    memoryPath: {
      recordsPath: "/home/user/.ioi/agentgres/memory",
    },
    events: [
      {
        kind: "memory.write",
        payload_summary: {
          recordId: "record-task",
          receipt_refs: ["receipt-task-event"],
        },
      },
    ],
    lateWriteBlocked: true,
    replayCursor: 17,
    completionReceiptRefs: ["receipt-policy"],
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.artifactCount, 4);
  assert.equal(panel.scratchCount, 1);
  assert.equal(panel.hasImplementationPlan, true);
  assert.equal(panel.hasTaskChecklist, true);
  assert.equal(panel.hasWalkthrough, true);
  assert.equal(panel.hasScratchRefs, true);
  assert.equal(panel.hasArtifactRefs, true);
  assert.equal(panel.hasReplayCursor, true);
  assert.equal(panel.brainOutsideWorkspace, true);
  assert.equal(panel.readOnlyAuditMode, true);
  assert.deepEqual(panel.receiptRefs, ["receipt-plan", "receipt-task-event", "receipt-policy"]);
  assert.equal(panel.rows.find((row) => row.artifactKind === "task").artifactRefs.includes("task.md"), true);
});

test("trajectory replay projection requires stable ids, empty cursor replay, and single side effect", () => {
  const projection = panels();
  const events = [
    { seq: 1, kind: "thread.started", status: "observed", receiptRefs: ["receipt-thread"] },
    { seq: 2, kind: "memory.write", status: "observed", receiptRefs: ["receipt-memory"] },
    { seq: 3, kind: "turn.completed", payload_summary: { status: "completed" } },
  ];
  const panel = projection.studioTrajectoryReplayPanelFromProjection({
    phase: "reconnect",
    threadId: "thread-one",
    expectedThreadId: "thread-one",
    events,
    eventsSinceCursor: [],
    memoryProjection: {
      records: [{ memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY }],
    },
    expectedReplayIds: [
      "trajectory-replay.step-1",
      "trajectory-replay.step-2",
      "trajectory-replay.step-3",
    ],
    replayCursor: 3,
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.guiReconnected, true);
  assert.equal(panel.trajectoryIdStable, true);
  assert.equal(panel.replayIdsStable, true);
  assert.equal(panel.replayFromCursorEmpty, true);
  assert.equal(panel.sideEffectCount, 1);
  assert.equal(panel.duplicateSideEffectCount, 0);
  assert.deepEqual(panel.receiptRefs, ["receipt-thread", "receipt-memory"]);
  assert.equal(panel.rows[1].summary, "Side-effect memory write recorded once.");
});

test("trajectory replay projection blocks duplicate side effects", () => {
  const projection = panels();
  const panel = projection.studioTrajectoryReplayPanelFromProjection({
    threadId: "thread-one",
    events: [{ seq: 1, kind: "memory.write" }],
    memoryProjection: {
      records: [
        { memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY },
        { memory_key: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY },
      ],
    },
    replayCursor: 1,
  });

  assert.equal(panel.status, "blocked");
  assert.equal(panel.sideEffectCount, 2);
  assert.equal(panel.duplicateSideEffectCount, 1);
});

test("session brain lifecycle orchestration preserves daemon envelopes and bridge proof", async () => {
  const requests = [];
  const bridgeRequests = [];
  const projection = {
    selectedModel: "auto",
    modelRoute: "route.local-first",
    sessionBrainPanels: [],
    replaySteps: [],
    runtimeCockpit: {},
  };
  const lifecycle = createStudioDurabilityPanels({
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.local",
    daemonRequestToken: () => "token-one",
    fetchStudioThreadEvents: async () => [
      {
        seq: 7,
        kind: "memory.write",
        payload_summary: { recordId: "record-plan", receipt_refs: ["receipt-plan-event"] },
      },
    ],
    firstArray,
    getStudioRuntimeProjection: () => projection,
    normalizeReceiptRefs,
    requestJson: async (endpoint, route, options = {}) => {
      requests.push({ endpoint, route, options });
      if (route === "/v1/threads") return { id: "thread-one" };
      if (route.endsWith("/memory/policy")) return { receiptRefs: ["receipt-policy"] };
      if (route.endsWith("/memory/path")) {
        return { recordsPath: "/home/user/.ioi/agentgres/memory" };
      }
      if (route.endsWith("/memory") && options.method === "GET") {
        return {
          workspace: "/workspace/project",
          policy: { readOnly: true },
          records: [
            { id: "record-plan", memoryKey: "implementation_plan", text: "Plan", receiptRefs: ["receipt-plan"] },
            { id: "record-task", memoryKey: "task", text: "Task", evidenceRefs: ["task.md"] },
            { id: "record-walkthrough", memoryKey: "walkthrough", text: "Walkthrough" },
            { id: "record-scratch", memoryKey: "scratch/eval-script", text: "Scratch" },
          ],
        };
      }
      if (route.endsWith("/memory") && options.method === "POST" && options.payload?.text?.includes("late write")) {
        throw new Error("memory_read_only");
      }
      return { receiptRefs: [`receipt-${requests.length}`] };
    },
    stringValue,
    studioMaxRuntimeEventSeq: (events) => Math.max(...events.map((event) => event.seq || 0)),
    studioRuntimeEventKind: (event = {}) => stringValue(event.kind || event.type, "runtime.event"),
    uniqueStrings,
    workspaceSummary: () => ({ path: "/workspace/project" }),
    workspacePath: () => "/workspace/project",
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const proof = await lifecycle.exerciseStudioSessionBrainLifecycle({ appendLine() {} });

  assert.equal(proof.passed, true);
  assert.equal(projection.threadId, "thread-one");
  assert.equal(projection.sessionBrainPanels.length, 1);
  assert.equal(projection.replaySteps.length, 6);
  assert.equal(projection.runtimeCockpit.replayStepDetailObserved, true);
  assert.equal(projection.runtimeCockpit.receiptTimelinePerStepObserved, true);
  assert.equal(requests[0].route, "/v1/threads");
  assert.equal(requests[0].options.payload.source, "agent_studio_session_brain_lifecycle");
  assert.equal(requests[0].options.payload.options.local.cwd, "/workspace/project");
  assert.equal(requests.filter((request) => request.route.endsWith("/memory") && request.options.method === "POST").length, 5);
  assert.equal(bridgeRequests[0][0], "studio.sessionBrainLifecycle.exercised");
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.equal(bridgeRequests[0][1].artifactWriteCount, 4);
  assert.equal(bridgeRequests[0][1].replayCursor, 7);
  assert.equal(bridgeRequests[0][2].source, "studio-session-brain-lifecycle");
});

test("trajectory replay lifecycle orchestration records one side effect and bridge proof", async () => {
  const requests = [];
  const bridgeRequests = [];
  const projection = {
    selectedModel: "auto",
    modelRoute: "route.local-first",
    trajectoryReplayPanels: [],
    engineReconnectBanners: [],
    replaySteps: [],
    runtimeCockpit: {},
  };
  const lifecycle = createStudioDurabilityPanels({
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.local",
    daemonRequestToken: () => "token-one",
    fetchStudioThreadEvents: async (_threadId, _output, options = {}) =>
      options.sinceSeq > 0
        ? []
        : [
            { seq: 1, kind: "thread.started", status: "observed", receiptRefs: ["receipt-thread"] },
            { seq: 2, kind: "memory.write", status: "observed", receiptRefs: ["receipt-memory"] },
          ],
    firstArray,
    getStudioRuntimeProjection: () => projection,
    normalizeReceiptRefs,
    requestJson: async (endpoint, route, options = {}) => {
      requests.push({ endpoint, route, options });
      if (route === "/v1/threads") return { id: "thread-one" };
      if (route.endsWith("/memory") && options.method === "GET") {
        return {
          records: [{ memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY }],
        };
      }
      return { receiptRefs: [`receipt-${requests.length}`] };
    },
    stringValue,
    studioMaxRuntimeEventSeq: (events) => Math.max(...events.map((event) => event.seq || 0)),
    studioRuntimeEventKind: (event = {}) => stringValue(event.kind || event.type, "runtime.event"),
    uniqueStrings,
    workspaceSummary: () => ({ path: "/workspace/project" }),
    workspacePath: () => "/workspace/project",
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const proof = await lifecycle.exerciseStudioTrajectoryReplayReconnect({ appendLine() {} });

  assert.equal(proof.passed, true);
  assert.equal(proof.phase, "create");
  assert.equal(projection.threadId, "thread-one");
  assert.equal(projection.trajectoryReplayPanels.length, 1);
  assert.equal(projection.engineReconnectBanners.length, 0);
  assert.equal(projection.replaySteps.length, 2);
  assert.equal(projection.runtimeCockpit.replayStepDetailObserved, true);
  assert.equal(projection.runtimeCockpit.receiptTimelinePerStepObserved, true);
  assert.equal(requests[0].route, "/v1/threads");
  assert.equal(requests[0].options.payload.source, "agent_studio_trajectory_replay_reconnect");
  assert.equal(requests[0].options.payload.options.local.cwd, "/workspace/project");
  const sideEffectRequest = requests.find((request) => request.route.endsWith("/memory") && request.options.method === "POST");
  assert.equal(sideEffectRequest.options.payload.memoryKey, STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY);
  assert.equal(bridgeRequests[0][0], "studio.trajectoryReplayReconnect.exercised");
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.equal(bridgeRequests[0][1].sideEffectWriteAttempted, true);
  assert.equal(bridgeRequests[0][1].sideEffectRecordCount, 1);
  assert.equal(bridgeRequests[0][1].replayCursor, 2);
  assert.equal(bridgeRequests[0][2].source, "studio-trajectory-replay-create");
});
