import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioWorkRunRows } = require("./work-run-rows.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createRows() {
  return createStudioWorkRunRows({
    compactStudioWhitespace: (value) => String(value || "").trim().replace(/\s+/g, " "),
    escapeHtml,
    firstArray: (value) => Array.isArray(value) ? value : [],
    formatStudioWorkDuration: (ms) => `${Math.round(Number(ms) / 1000)}s`,
    getHunkApprovalId: () => "approval-default",
    studioCommandRowHasOutput: (command) => Boolean(command?.stdout || command?.stderr || command?.output),
    studioPendingWorkLabelForTool: (toolId, _label, status) => `${status}:${toolId}`,
    studioPublicOutputBlock: (value) => String(value || "").replace(/\/tmp\/secret/g, "<tmp>"),
    studioPublicWorkspacePath: (value) => String(value || "").replace("/workspace/", ""),
    studioSanitizePublicAssistantText: (value) => String(value || "").replace(/\/tmp\/secret/g, "<tmp>"),
    studioSourceChipRows: (sources) => sources.map((source) => `<span>${escapeHtml(source.label || source.url || "")}</span>`).join(""),
    stringValue: (value, fallback = "") => value === null || value === undefined ? fallback : String(value),
  });
}

test("work run rows classify command surfaces and public action labels", () => {
  const rows = createRows();

  assert.equal(rows.studioCommandSurfaceLabel({ toolId: "shell__run" }), "Shell");
  assert.equal(rows.studioCommandSurfaceLabel({ toolId: "browser__open" }), "Browser");
  assert.equal(rows.studioCommandSurfaceLabel({ toolId: "file__read" }), "File");
  assert.equal(rows.studioCommandPublicActionLabel({ label: "command", status: "running" }), "Running command");
  assert.equal(rows.studioCommandPublicActionLabel({ label: "file__read", status: "completed" }), "completed:file__read");
  assert.equal(rows.studioCommandHeadline({ label: "command", status: "completed", durationMs: 2000 }), "Ran command for 2s");
});

test("work summary rows sanitize public text, source chips, and tmp paths", () => {
  const rows = createRows();
  const html = rows.studioWorkSummaryRows({
    lines: ["Patched /tmp/secret"],
  });

  assert.match(html, /Patched workspace file/);
  assert.doesNotMatch(html, /\/tmp\/secret/);

  const richer = rows.studioWorkSummaryRows({
    workRows: [{
      headline: "Read /tmp/secret",
      summary: "Done <ok>",
      sourceChips: [{ label: "Docs <1>" }],
      excerptPreview: "Edited /tmp/secret",
    }],
  });
  assert.match(richer, /Read workspace file/);
  assert.match(richer, /Done &lt;ok&gt;/);
  assert.match(richer, /Docs &lt;1&gt;/);
});

test("work command output rows settle running commands and filter empty completed rows", () => {
  const rows = createRows();
  const html = rows.studioWorkCommandOutputRows({
    status: "completed",
    commandOutputs: [
      { toolId: "shell__run", label: "command", status: "running", stdout: "ok", exitCode: 0, durationMs: 3000 },
      { toolId: "shell__run", label: "command", status: "completed" },
    ],
  });

  assert.match(html, /data-testid="studio-command-output-row"/);
  assert.match(html, /Ran command/);
  assert.match(html, /Shell/);
  assert.match(html, /exit 0/);
  assert.match(html, /3s/);
  assert.doesNotMatch(html, />No output</);
});

test("work diff rows preserve hunk controls, workspace path, and approval fallback", () => {
  const rows = createRows();
  const html = rows.studioWorkRecordDiffRows({
    diffHunks: [{
      change_id: "change-1",
      hunk_index: 2,
      file: "/workspace/src/app.js",
      before: "-old",
      after: "+new",
      stale: true,
      stale_reason: "changed",
      rollback_available: true,
    }],
  });

  assert.match(html, /data-testid="studio-inline-diff-hunks"/);
  assert.match(html, /src\/app\.js/);
  assert.match(html, /data-approval-id="approval-default"/);
  assert.match(html, /data-studio-hunk-decision="approve"/);
  assert.match(html, /data-studio-hunk-decision="reject"/);
  assert.match(html, /data-studio-hunk-decision="rollback"/);
  assert.match(html, /data-hunk-index="2"/);
});
