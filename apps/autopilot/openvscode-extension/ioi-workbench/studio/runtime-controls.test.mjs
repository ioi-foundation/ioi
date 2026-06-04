import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioRuntimeControls } = require("./runtime-controls.js");

function createHarness({ projection = {}, requestJson } = {}) {
  const state = {
    threadId: "thread-one",
    turnId: "turn-one",
    pending: true,
    status: "active",
    timeline: [],
    runtimeCockpit: {},
    ...projection,
  };
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const receipts = [];
  const timeline = [];
  const bridgeRequests = [];
  const refreshes = [];
  let recomputeCount = 0;
  const controls = createStudioRuntimeControls({
    appendStudioReceiptsFromResponse: (response, kind, detail) => receipts.push({ response, kind, detail }),
    appendStudioTimeline: (...args) => timeline.push(args),
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    getStudioRuntimeProjection: () => state,
    recomputeStudioRuntimeCockpitAchieved: () => {
      recomputeCount += 1;
    },
    refreshStudioPanelHtml: async (...args) => refreshes.push(args),
    requestJson,
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });
  return {
    bridgeRequests,
    controls,
    output,
    receipts,
    refreshes,
    state,
    timeline,
    get recomputeCount() { return recomputeCount; },
  };
}

test("runtime controls stop turn through daemon and bridge envelopes", async () => {
  const requests = [];
  const harness = createHarness({
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return { runtime_control: { action: "stop" }, receipt_refs: ["receipt-stop"] };
    },
  });

  await harness.controls.stopStudioTurn(harness.output);

  assert.equal(harness.state.pending, false);
  assert.equal(harness.state.status, "interrupted");
  assert.equal(harness.state.timeline[0].label, "Stop requested");
  assert.equal(harness.state.runtimeCockpit.stopControlObserved, true);
  assert.equal(harness.state.runtimeCockpit.stopResumeObserved, false);
  assert.equal(harness.recomputeCount, 1);
  assert.equal(requests[0].route, "/v1/threads/thread-one/turns/turn-one/interrupt");
  assert.equal(requests[0].options.payload.runtimeControlAction, "stop");
  assert.equal(harness.receipts[0].kind, "session_stop");
  assert.equal(harness.timeline[0][0], "Runtime stop control");
  assert.equal(harness.bridgeRequests[0][0], "chat.stop");
  assert.equal(harness.bridgeRequests[0][1].runtimeAuthority, "daemon-owned");
  assert.equal(harness.bridgeRequests[0][1].ownsRuntimeState, false);
  assert.equal(harness.bridgeRequests[0][2].source, "agent-studio-stop");
  assert.equal(harness.refreshes.length, 1);
});

test("runtime controls resume turn through daemon and bridge envelopes", async () => {
  const requests = [];
  const harness = createHarness({
    projection: { runtimeCockpit: { stopControlObserved: true } },
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return { runtimeControl: { action: "resume" }, receiptRefs: ["receipt-resume"] };
    },
  });

  await harness.controls.resumeStudioTurn(harness.output);

  assert.equal(harness.state.status, "completed");
  assert.equal(harness.state.runtimeCockpit.resumeControlObserved, true);
  assert.equal(harness.state.runtimeCockpit.stopResumeObserved, true);
  assert.equal(harness.recomputeCount, 2);
  assert.equal(harness.timeline[0][0], "Resume requested");
  assert.equal(harness.timeline[1][0], "Runtime resume control");
  assert.equal(requests[0].route, "/v1/threads/thread-one/resume");
  assert.equal(requests[0].options.payload.reason, "operator_resume");
  assert.equal(harness.receipts[0].kind, "session_resume");
  assert.equal(harness.bridgeRequests[0][0], "chat.resume");
  assert.equal(harness.bridgeRequests[0][1].reason, "operator_resume");
  assert.equal(harness.bridgeRequests[0][2].source, "agent-studio-resume");
  assert.equal(harness.refreshes.length, 1);
});

test("runtime controls report daemon route failures without losing bridge control", async () => {
  const harness = createHarness({
    requestJson: async () => {
      throw new Error("daemon offline");
    },
  });

  await harness.controls.stopStudioTurn(harness.output);
  await harness.controls.resumeStudioTurn(harness.output);

  assert.match(harness.output.lines[0], /stop projection unavailable: daemon offline/);
  assert.match(harness.output.lines[1], /resume projection unavailable: daemon offline/);
  assert.equal(harness.bridgeRequests[0][0], "chat.stop");
  assert.equal(harness.bridgeRequests[1][0], "chat.resume");
  assert.equal(harness.timeline.some((entry) => entry[0] === "Resume projection unavailable"), true);
  assert.equal(harness.refreshes.length, 2);
});
