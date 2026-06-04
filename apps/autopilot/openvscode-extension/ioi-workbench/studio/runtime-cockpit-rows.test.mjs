import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioRuntimeCockpitRows } = require("./runtime-cockpit-rows.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createRows(state) {
  return createStudioRuntimeCockpitRows({
    STUDIO_RUNTIME_VISIBILITY: { inlineAction: "inline-action" },
    escapeHtml,
    firstArray: (value) => Array.isArray(value) ? value : [],
    getHunkApprovalId: () => "approval-default",
    getStudioRuntimeProjection: () => state,
    studioCommandHeadline: (command) => command.headline || command.label || "Ran command",
    stringValue: (value, fallback = "") => value === null || value === undefined ? fallback : String(value),
  });
}

test("runtime cockpit rows render diff controls and compact hunk prompt", () => {
  const rows = createRows({
    diffHunks: [{
      change_id: "change-1",
      hunk_index: 3,
      file: "src/app.js",
      before: "-old",
      after: "+new",
      stale: true,
      stale_reason: "changed",
      acceptAvailable: true,
      rollback_available: true,
    }],
    policyLeases: [],
  });

  const diffHtml = rows.studioDiffRows();
  assert.match(diffHtml, /data-testid="studio-inline-diff-hunks"/);
  assert.match(diffHtml, /data-approval-id="approval-default"/);
  assert.match(diffHtml, /data-studio-hunk-decision="rollback"/);
  assert.match(diffHtml, /data-hunk-index="3"/);

  const compactHtml = rows.studioCompactRuntimeStatusRows();
  assert.match(compactHtml, /data-testid="studio-native-hunk-review-inline"/);
  assert.match(compactHtml, /1 hunk waiting for review/);
});

test("runtime cockpit rows render policy lease and compact policy prompt", () => {
  const rows = createRows({
    diffHunks: [],
    policyLeases: [{
      status: "blocked",
      title: "Permission <needed>",
      reason: "Review & approve",
      action: "file.write",
      didExecute: false,
      decision: "denied",
      afterRevokeBlocked: true,
      receiptRefs: ["receipt-1"],
    }],
  });

  const leaseHtml = rows.studioPolicyLeaseRows();
  assert.match(leaseHtml, /data-testid="studio-policy-lease-dialog"/);
  assert.match(leaseHtml, /Permission &lt;needed&gt;/);
  assert.match(leaseHtml, /Review &amp; approve/);
  assert.match(leaseHtml, /data-lease-after-revoke-blocked="true"/);

  const compactHtml = rows.studioCompactRuntimeStatusRows();
  assert.match(compactHtml, /data-testid="studio-policy-prompt-actionable"/);
  assert.match(compactHtml, /data-runtime-visibility="inline-action"/);
});

test("runtime cockpit rows render command, diagnostics, browser, and worker cards", () => {
  const rows = createRows({
    commandOutputs: [{ label: "npm test", status: "completed", stdout: "ok", exitCode: 0 }],
    diagnosticGates: [{ title: "Node check", status: "completed", detail: "Exit 0", receiptRefs: ["receipt-diagnostics"] }],
    browserCards: [{ title: "Browser <ready>", status: "observed", detail: "Page loaded" }],
    workerCards: [{ title: "Worker status", status: "completed", detail: "Done", receiptRefs: ["receipt-worker"] }],
  });

  assert.match(rows.studioCommandOutputRows(), /data-testid="studio-command-output-card"/);
  assert.match(rows.studioCommandOutputRows(), /exit 0/);
  assert.match(rows.studioDiagnosticsRows(), /data-testid="studio-diagnostics-test-gate"/);
  assert.match(rows.studioDiagnosticsRows(), /receipt-diagnostics/);
  assert.match(rows.studioBrowserWorkerRows(), /Browser &lt;ready&gt;/);
  assert.match(rows.studioBrowserWorkerRows(), /data-testid="studio-worker-status-card"/);
  assert.match(rows.studioBrowserWorkerRows(), /receipt-worker/);
});

test("runtime cockpit rows render recent action cards with receipts", () => {
  const rows = createRows({
    actionCards: [{ toolId: "file.write", title: "Write file", status: "proposed", receiptRefs: ["receipt-action"] }],
  });

  const html = rows.studioActionCardRows();
  assert.match(html, /data-testid="studio-tool-proposal-card"/);
  assert.match(html, /data-tool-id="file.write"/);
  assert.match(html, /receipt-action/);
});
