import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioHunkLifecycle } = require("./hunk-lifecycle.js");

function createHarness({ projection = {}, requestJson, invokeStudioDaemonTool, executeCommand } = {}) {
  const state = {
    threadId: "thread-one",
    turnId: "turn-one",
    modelRoute: "route.local-first",
    approvalId: "approval-default",
    diffHunks: [{ changeId: "change-one", status: "pending" }],
    approvals: [],
    timeline: [],
    runtimeCockpit: {},
    ...projection,
  };
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const receipts = [];
  const timeline = [];
  const bridgeRequests = [];
  const refreshes = [];
  const workspaceRefreshes = [];
  let recomputeCount = 0;
  const lifecycle = createStudioHunkLifecycle({
    appendStudioReceipts: (items) => receipts.push(...items),
    appendStudioReceiptsFromResponse: (response, kind, detail) => receipts.push({ response, kind, detail }),
    appendStudioTimeline: (...args) => timeline.push(args),
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    ensureStudioDaemonThread: async () => state,
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => state,
    invokeStudioDaemonTool,
    recomputeStudioRuntimeCockpitAchieved: () => {
      recomputeCount += 1;
    },
    refreshStudioPanelHtml: async (...args) => refreshes.push(args),
    refreshStudioWorkspaceChangeReviewsFromDaemon: async (...args) => workspaceRefreshes.push(args),
    requestJson,
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    studioApprovalTurnPayload: () => ({ turn_id: "turn-one" }),
    STUDIO_APPROVAL_ID: "approval-default",
    uniqueStrings: (values = []) => [...new Set(values.filter(Boolean))],
    vscode: { commands: { executeCommand: executeCommand || (async () => {}) } },
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });
  return {
    bridgeRequests,
    lifecycle,
    output,
    receipts,
    refreshes,
    state,
    timeline,
    workspaceRefreshes,
    get recomputeCount() { return recomputeCount; },
  };
}

test("hunk lifecycle accepts workspace change through daemon tool and bridge envelope", async () => {
  const toolCalls = [];
  const harness = createHarness({
    invokeStudioDaemonTool: async (...args) => {
      toolCalls.push(args);
      return { status: "completed", receipt_refs: ["receipt-change"] };
    },
  });

  await harness.lifecycle.handleStudioHunkDecision("approve", { changeId: "change-one", approvalId: "approval-one" }, harness.output);

  assert.equal(toolCalls[0][1], "workspace_change__accept");
  assert.deepEqual(toolCalls[0][2], { change_id: "change-one" });
  assert.equal(harness.state.hunkDecision, "approve");
  assert.equal(harness.state.diffHunks[0].status, "approved");
  assert.equal(harness.state.approvals[0].status, "approved");
  assert.equal(harness.state.runtimeCockpit.hunkAcceptRejectReceiptsObserved, true);
  assert.equal(harness.recomputeCount, 1);
  assert.equal(harness.receipts[0].kind, "workspace_change_approve");
  assert.equal(harness.bridgeRequests[0][0], "chat.hunkDecision");
  assert.equal(harness.bridgeRequests[0][1].runtimeAuthority, "daemon-owned");
  assert.equal(harness.bridgeRequests[0][1].ownsRuntimeState, false);
  assert.equal(harness.bridgeRequests[0][2].source, "agent-studio-inline-diff");
  assert.equal(harness.workspaceRefreshes.length, 1);
  assert.equal(harness.refreshes.length, 1);
});

test("hunk lifecycle posts approval decision and receipts fallback path", async () => {
  const requests = [];
  const harness = createHarness({
    projection: { diffHunks: [{ status: "pending" }] },
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return { receipt_refs: ["receipt-a", "receipt-a"], receiptRefs: ["receipt-b"] };
    },
  });

  await harness.lifecycle.handleStudioHunkDecision("reject", { approvalId: "approval-two" }, harness.output);

  assert.equal(requests[0].route, "/v1/threads/thread-one/approvals/approval-two/decision");
  assert.equal(requests[0].options.payload.decision, "reject");
  assert.equal(requests[0].options.payload.source, "agent_studio_inline_diff");
  assert.equal(harness.state.hunkDecision, "reject");
  assert.equal(harness.state.diffHunks[0].status, "rejected");
  assert.equal(harness.state.approvals[0].status, "rejected");
  assert.deepEqual(harness.receipts.map((receipt) => receipt.id), ["receipt-a", "receipt-b"]);
  assert.equal(harness.state.runtimeCockpit.hunkAcceptRejectReceiptsObserved, true);
  assert.equal(harness.bridgeRequests[0][1].decision, "reject");
  assert.equal(harness.refreshes.length, 1);
});

test("hunk lifecycle records blocked decision and still refreshes", async () => {
  const harness = createHarness({
    requestJson: async () => {
      throw new Error("approval offline");
    },
  });

  await harness.lifecycle.handleStudioHunkDecision("approve", {}, harness.output);

  assert.equal(harness.state.timeline.at(-1).label, "Hunk decision blocked");
  assert.match(harness.state.timeline.at(-1).detail, /approval offline/);
  assert.equal(harness.refreshes.length, 1);
});

test("hunk lifecycle navigates native hunk changes and reports command errors", async () => {
  const commands = [];
  const harness = createHarness({
    executeCommand: async (command) => {
      commands.push(command);
      throw new Error("no editor");
    },
  });

  await harness.lifecycle.navigateStudioHunk("previous", harness.output);

  assert.deepEqual(commands, ["workbench.action.compareEditor.previousChange"]);
  assert.equal(harness.state.runtimeCockpit.hunkNavigationObserved, true);
  assert.equal(harness.recomputeCount, 1);
  assert.equal(harness.timeline[0][0], "Native hunk navigation");
  assert.match(harness.output.lines[0], /native hunk navigation unavailable: no editor/);
  assert.equal(harness.workspaceRefreshes.length, 1);
  assert.equal(harness.refreshes.length, 1);
});
