import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioRuntimeCockpitLifecycle } = require("./runtime-cockpit-lifecycle.js");

function createProjection(overrides = {}) {
  return {
    threadId: "thread-one",
    turnId: "turn-one",
    modelRoute: "route.local-first",
    runtimeCockpit: {},
    policyLeases: [],
    commandOutputs: [],
    diagnosticGates: [],
    approvals: [],
    diffHunks: [],
    browserCards: [],
    workerCards: [],
    ...overrides,
  };
}

test("runtime cockpit lifecycle projects daemon proof lanes and replay refresh", async () => {
  const projection = createProjection();
  const timeline = [];
  const receipts = [];
  const openedHunks = [];
  const requests = [];
  const invokedTools = [];
  let replayRefreshed = false;
  let policyDenied = false;

  const lifecycle = createStudioRuntimeCockpitLifecycle({
    appendStudioReceiptsFromResponse: (response, kind, detail) => receipts.push({ response, kind, detail }),
    appendStudioTimeline: (...args) => timeline.push(args),
    commandOutputFromToolResponse: (toolId, response) => ({
      id: `command-${toolId}`,
      toolId,
      label: toolId,
      status: response.status,
      stdout: response.stdout || "",
      stderr: "",
      exitCode: response.exitCode ?? 0,
      durationMs: 12,
      receiptRefs: response.receipt_refs || [],
    }),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => projection,
    invokeStudioDaemonTool: async (threadId, toolId, input, output, options) => {
      invokedTools.push({ threadId, toolId, input, output, options });
      if (toolId === "lsp.diagnostics") {
        return { status: "completed", stdout: "ok", exitCode: 0, receipt_refs: ["receipt-diagnostics"] };
      }
      if (toolId === "file.apply_patch") {
        return { status: "completed", hunk: "patch", receipt_refs: ["receipt-patch"] };
      }
      throw new Error(`unexpected tool ${toolId}`);
    },
    normalizeReceiptRefs: (...records) => records.flatMap((record) => {
      const refs = record?.receipt_refs || record?.receiptRefs || [];
      return Array.isArray(refs) ? refs : [];
    }),
    openStudioNativeDiffPreview: async (hunk) => openedHunks.push(hunk),
    patchPreviewHunkFromToolResponse: (response, targetPath) => ({
      file: targetPath,
      title: "Patch preview",
      status: response.status,
      before: "- before",
      after: "+ after",
    }),
    recomputeStudioRuntimeCockpitAchieved: () => {
      projection.runtimeCockpit.achieved = true;
    },
    refreshStudioReplayStepsFromProjection: () => {
      replayRefreshed = true;
    },
    requestAndDenyStudioPolicyLease: async () => {
      policyDenied = true;
      projection.runtimeCockpit.policyLeaseDialogObserved = true;
    },
    requestJson: async (endpoint, route, options = {}) => {
      requests.push({ endpoint, route, options });
      if (route.endsWith("/approvals")) {
        return { approval_id: "approval-one", receipt_refs: ["receipt-approval"] };
      }
      if (route === "/v1/computer-use/browser-discovery?probe=false&include_tabs=false") {
        return { browsers: [{ id: "browser-one" }] };
      }
      if (route.endsWith("/subagents") && options.method === "POST") {
        return { subagent_id: "worker-one", status: "spawned", receipt_refs: ["receipt-worker"] };
      }
      throw new Error(`unexpected route ${route}`);
    },
    studioApprovalTurnPayload: () => ({ turnId: "turn-one" }),
    studioRuntimeCockpitPatchTargetFromPrompt: () => "src/status-labels.mjs",
    STUDIO_APPROVAL_ID: "approval-default",
    STUDIO_POLICY_LEASE_ID: "policy-default",
  });

  await lifecycle.projectStudioRuntimeCockpit(
    "repair src/status-labels.mjs",
    { providerStream: true, chunkCount: 2, events: [{ receipt_refs: ["receipt-event"] }] },
    { appendLine() {} },
  );

  assert.equal(policyDenied, true);
  assert.equal(projection.runtimeCockpit.modelBackedStreamingObserved, true);
  assert.equal(projection.runtimeCockpit.policyLeaseDialogObserved, true);
  assert.equal(projection.runtimeCockpit.sandboxCommandOutputStreamObserved, true);
  assert.equal(projection.runtimeCockpit.sandboxCommandReceiptObserved, true);
  assert.equal(projection.runtimeCockpit.diagnosticsTestGateObserved, true);
  assert.equal(projection.runtimeCockpit.browserStatusObserved, true);
  assert.equal(projection.runtimeCockpit.workerStatusObserved, true);
  assert.equal(projection.runtimeCockpit.achieved, true);
  assert.equal(projection.commandOutputs[0].toolId, "lsp.diagnostics");
  assert.equal(projection.diagnosticGates[0].receiptRefs[0], "receipt-diagnostics");
  assert.equal(projection.hunkApprovalId, "approval-one");
  assert.equal(projection.diffHunks[0].approvalId, "approval-one");
  assert.equal(openedHunks[0].file, "src/status-labels.mjs");
  assert.equal(projection.browserCards[0].status, "observed");
  assert.match(projection.workerCards[0].detail, /worker-one spawned/);
  assert.equal(replayRefreshed, true);
  assert.deepEqual(invokedTools.map((tool) => tool.toolId), ["lsp.diagnostics", "file.apply_patch"]);
  assert.deepEqual(receipts.map((record) => record.kind), ["patch_preview", "approval_required", "worker_spawn"]);
  assert.equal(timeline.at(-1)[0], "Runtime cockpit evidence ready");
  assert.equal(requests[0].route, "/v1/threads/thread-one/approvals");
});

test("runtime cockpit lifecycle blocks cleanly without a daemon thread", async () => {
  const projection = createProjection({ threadId: "" });
  const timeline = [];
  const lifecycle = createStudioRuntimeCockpitLifecycle({
    appendStudioTimeline: (...args) => timeline.push(args),
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => projection,
    normalizeReceiptRefs: () => [],
  });

  await lifecycle.projectStudioRuntimeCockpit("anything", {}, { appendLine() {} });

  assert.equal(timeline.length, 1);
  assert.equal(timeline[0][0], "Runtime cockpit blocked");
  assert.equal(projection.commandOutputs.length, 0);
});
