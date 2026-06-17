import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioRuntimeRailRows } = require("./runtime-rail-rows.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createRows(state) {
  return createStudioRuntimeRailRows({
    escapeHtml,
    getStudioRuntimeProjection: () => state,
    studioParityPlusPanelRowsFromRenderer: (projection) => `<section data-testid="parity">${escapeHtml(projection.status || "")}</section>`,
  });
}

test("runtime rail rows render timeline, history, approval, and terminal safely", () => {
  const rows = createRows({
    timeline: [{ status: "blocked", label: "Policy <gate>", detail: "Needs & review" }],
    history: [{ title: "Current <session>", status: "idle", id: "studio-session-current" }],
    approvals: [{ id: "approval-1", label: "Permission <needed>", detail: "Review & approve", status: "pending" }],
    terminal: [{ label: "Shell <run>", detail: "exit & 0" }],
  });

  assert.match(rows.studioTimelineRows(), /Policy &lt;gate&gt;/);
  assert.match(rows.studioTimelineRows(), /Needs &amp; review/);
  assert.match(rows.studioHistoryRows(), /Current &lt;session&gt;/);
  assert.match(rows.studioApprovalRows(), /data-approval-id="approval-1"/);
  assert.match(rows.studioApprovalRows(), /Permission &lt;needed&gt;/);
  assert.match(rows.studioTerminalRows(), /Shell &lt;run&gt;/);
});

test("runtime rail rows render receipt fallback, replay fallback, and parity projection", () => {
  const rows = createRows({ receipts: [], replaySteps: [], status: "ready" });

  assert.match(rows.studioReceiptRows(), /receipt\.pending/);
  assert.match(rows.studioReplayRows(), /Replay pending/);
  assert.match(rows.studioParityPlusPanelRows(), /data-testid="parity"/);
  assert.match(rows.studioParityPlusPanelRows(), /ready/);
});

test("runtime rail rows render recent receipts and replay rows", () => {
  const rows = createRows({
    receipts: Array.from({ length: 9 }, (_, index) => ({
      id: `receipt-${index + 1}`,
      kind: "tool",
      summary: `Receipt ${index + 1}`,
    })),
    replaySteps: [{ id: "event-1", kind: "runtime.event", summary: "Observed." }],
  });

  const receiptHtml = rows.studioReceiptRows();
  assert.doesNotMatch(receiptHtml, /receipt-1/);
  assert.match(receiptHtml, /receipt-9/);
  assert.match(rows.studioReplayRows(), /event-1/);
  assert.match(rows.studioReplayRows(), /Observed\./);
});
