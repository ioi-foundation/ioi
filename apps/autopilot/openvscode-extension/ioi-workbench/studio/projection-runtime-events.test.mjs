import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioRuntimeEventProjection } = require("./projection-runtime-events.js");

function createHarness(state = { timeline: [], runtimeEvents: [], runtimeCockpit: {}, receipts: [] }) {
  const appendedReceipts = [];
  const harness = createStudioRuntimeEventProjection({
    appendStudioReceipts: (receipts) => {
      appendedReceipts.push(...receipts);
      state.receipts.push(...receipts);
    },
    classifyStudioRuntimeEvent: (event) => /policy|approval/.test(String(event.kind || "")) ? "inline-action" : "inline-summary",
    getStudioRuntimeProjection: () => state,
    normalizeReceiptRefs: (source) => {
      if (Array.isArray(source?.receiptRefs)) return source.receiptRefs;
      if (Array.isArray(source?.receipt_refs)) return source.receipt_refs;
      return [];
    },
  });
  return { appendedReceipts, harness, state };
}

test("runtime event projection appends timeline rows with extra metadata", () => {
  const { harness, state } = createHarness();

  harness.appendStudioTimeline("Tool proposal observed", "file.read", "pending", { toolId: "file.read" });

  assert.equal(state.timeline.length, 1);
  assert.equal(state.timeline[0].label, "Tool proposal observed");
  assert.equal(state.timeline[0].detail, "file.read");
  assert.equal(state.timeline[0].status, "pending");
  assert.equal(state.timeline[0].toolId, "file.read");
  assert.match(state.timeline[0].at, /^\d{4}-\d{2}-\d{2}T/);
});

test("runtime event projection normalizes event aliases and projects receipt timeline rows", () => {
  const { appendedReceipts, harness, state } = createHarness();

  harness.appendStudioRuntimeEvent({
    event_id: "event-1",
    event_kind: "policy.lease",
    payload_summary: {
      status: "requires_approval",
      summary: "Approval required.",
    },
    receipt_refs: ["receipt-1"],
  });

  assert.deepEqual(state.runtimeEvents[0], {
    id: "event-1",
    kind: "policy.lease",
    status: "requires_approval",
    summary: "Approval required.",
    receiptRefs: ["receipt-1"],
    raw: {
      event_id: "event-1",
      event_kind: "policy.lease",
      payload_summary: {
        status: "requires_approval",
        summary: "Approval required.",
      },
      receipt_refs: ["receipt-1"],
    },
    visibility: "inline-action",
  });
  assert.deepEqual(appendedReceipts, [{
    id: "receipt-1",
    kind: "policy.lease",
    summary: "Approval required.",
  }]);
});

test("runtime event projection ignores non-object events and appends response receipts", () => {
  const { appendedReceipts, harness, state } = createHarness();

  harness.appendStudioRuntimeEvent(null);
  harness.appendStudioReceiptsFromResponse({ receiptRefs: ["receipt-2"] }, "tool.file", "Tool receipt.");

  assert.deepEqual(state.runtimeEvents, []);
  assert.deepEqual(appendedReceipts, [{
    id: "receipt-2",
    kind: "tool.file",
    summary: "Tool receipt.",
  }]);
});

test("runtime cockpit recompute preserves full achieved gate semantics", () => {
  const required = {
    modelBackedStreamingObserved: true,
    realDaemonToolProposalObserved: true,
    policyLeaseDialogObserved: true,
    policyDeniedActionDidNotExecute: true,
    sandboxCommandOutputStreamObserved: true,
    sandboxCommandReceiptObserved: true,
    inlineDiffOverlayObserved: true,
    hunkNavigationObserved: true,
    hunkAcceptRejectReceiptsObserved: true,
    stopResumeObserved: true,
    diagnosticsTestGateObserved: true,
    receiptTimelinePerStepObserved: true,
    replayStepDetailObserved: true,
    projectionOnlyRuntimeRejected: true,
    browserStatusObserved: true,
    workerStatusObserved: true,
  };
  const { harness, state } = createHarness({ timeline: [], runtimeEvents: [], runtimeCockpit: { ...required }, receipts: [] });

  assert.equal(harness.recomputeStudioRuntimeCockpitAchieved(), true);
  assert.equal(state.runtimeCockpit.achieved, true);

  state.runtimeCockpit.workerStatusObserved = false;
  assert.equal(harness.recomputeStudioRuntimeCockpitAchieved(), false);
  assert.equal(state.runtimeCockpit.achieved, false);
});
